// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tailsql implements an HTTP API and "playground" UI for sending SQL
// queries to a collection of local and/or remote databases, and rendering the
// results for human consumption.
//
// # API
//
// The main UI is served from "/", static assets from "/static/".
// The following path and query parameters are understood:
//
//   - The q parameter carries an SQL query. The syntax of the query depends on
//     the src (see below). See also "Named Queries" below.
//
//   - The src parameter names which database to query against. Its values are
//     defined when the server is set up. If src is omitted, the first database
//     is used as a default.
//
//   - "/" serves output as HTML for the UI. In this format the query (q) may
//     be empty (no output will be displayed).
//
//   - "/json" serves output as JSON objects, one per row.  In this format the
//     query (q) must be non-empty.
//
//   - "/csv" serves output as comma-separated values, the first line giving
//     the column names, the remaining lines the rows. In this format the query
//     (q) must be non-empty.
//
//   - "/meta" serves a JSON blob of metadata about available data sources.
//
// Calls to the /json endpoint must set the Sec-Tailsql header to "1". This
// prevents browser scripts from directing queries to this endpoint.
//
// Calls to /csv must either set Sec-Tailsql to "1" or include a tailsqlQuery=1
// same-site cookie.
//
// Calls to the UI with a non-empty query must include the tailsqlQuery=1
// same-site cookie, which is set when the UI first loads. This averts simple
// cross-site redirection tricks.
//
// # Named Queries
//
// The query processor treats a query of the form "named:<string>" as a named
// query.  Named queries are SQL queries pre-defined by the database, to allow
// users to make semantically stable queries without relying on a specific
// schema format.
//
// # Meta Queries
//
// The query processor treats a query "meta:named" as a meta-query to report
// the names and content of all named queries, regardless of source.
package tailsql

import (
	"context"
	"database/sql"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tailscale/setec/client/setec"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
)

//go:embed ui.tmpl
var uiTemplate string

//go:embed static
var staticFS embed.FS

var ui = template.Must(template.New("sql").Funcs(template.FuncMap{
	"div": func(a, b int) int {
		if b == 0 {
			return 0
		}
		return a / b
	},
	"formatDuration": func(seconds float64) string {
		duration := time.Duration(seconds * float64(time.Second))
		if duration < time.Microsecond {
			return fmt.Sprintf("%dns", duration.Nanoseconds())
		}
		if duration < time.Millisecond {
			return fmt.Sprintf("%.2fµs", float64(duration.Nanoseconds())/1000)
		}
		if duration < time.Second {
			return fmt.Sprintf("%.2fms", float64(duration.Nanoseconds())/1000000)
		}
		return fmt.Sprintf("%.2fs", seconds)
	},
}).Parse(uiTemplate))

// noBrowsersHeader is a header that must be set in requests to the API
// endpoints that are intended to be accessed not from browsers.  If this
// header is not set to a non-empty value, those requests will fail.
const noBrowsersHeader = "Sec-Tailsql"

// maxRecentQueries is the maximum number of recent queries to display in the UI
const maxRecentQueries = 10

// baseRetryDelay is the base delay for exponential backoff
const baseRetryDelay = 50 * time.Millisecond

// maxRetryDelay is the maximum delay between retries
const maxRetryDelay = 2 * time.Second

// getBackoffDelay returns the delay to use for a retry attempt with jitter
func getBackoffDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	// Calculate exponential delay: baseDelay * 2^attempt
	delay := baseRetryDelay * time.Duration(1<<uint(attempt))
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	// Add jitter: randomly adjust by ±25%
	jitter := time.Duration(float64(delay) * (0.5 - rand.Float64()))
	return delay + jitter
}

// siteAccessCookie is a cookie that must be presented with any request from a
// browser that includes a query, and does not have the noBrowsersHeader.
var siteAccessCookie = &http.Cookie{
	Name: "tailsqlQuery", Value: "1", SameSite: http.SameSiteLaxMode, HttpOnly: true,
}

// contentSecurityPolicy is the CSP value sent for all requests to the UI.
// Adapted from https://owasp.org/www-community/controls/Content_Security_Policy.
const contentSecurityPolicy = `default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';`

func requestHasSiteAccess(r *http.Request) bool {
	c, err := r.Cookie(siteAccessCookie.Name)
	return err == nil && c.Value == siteAccessCookie.Value
}

func requestHasSecureHeader(r *http.Request) bool {
	return r.Header.Get(noBrowsersHeader) != ""
}

// Server is a server for the tailsql API.
type Server struct {
	lc        LocalClient
	state     *localState // local state database (for query logs)
	self      string      // if non-empty, the local state source label
	links     []UILink
	prefix    string
	rules     []UIRewriteRule
	authorize func(string, *apitype.WhoIsResponse) error
	qcheck    func(Query) (Query, error)
	qtimeout  time.Duration
	logf      logger.Logf

	mu  sync.Mutex
	dbs []*setec.Updater[*dbHandle]
}

// NewServer constructs a new server with the given Options.
func NewServer(opts Options) (*Server, error) {
	// Check the validity of the sources, and get any secret names they require
	// from the secrets service. If there are any, we also require that a
	// secrets service URL is configured.
	sec, err := opts.CheckSources()
	if err != nil {
		return nil, fmt.Errorf("checking sources: %w", err)
	} else if len(sec) != 0 && opts.SecretStore == nil {
		return nil, fmt.Errorf("have %d named secrets but no secret store", len(sec))
	}

	dbs, err := opts.openSources(context.Background(), opts.SecretStore)
	if err != nil {
		return nil, fmt.Errorf("opening sources: %w", err)
	}
	state, err := opts.localState()
	if err != nil {
		return nil, fmt.Errorf("local state: %w", err)
	}
	if state != nil && opts.LocalSource != "" {
		dbs = append(dbs, setec.StaticUpdater(&dbHandle{
			src:   opts.LocalSource,
			label: "tailsql local state",
			db:    state,
			named: map[string]string{
				"schema": `select * from sqlite_schema`,
			},
		}))
	}

	if opts.Metrics != nil {
		addMetrics(opts.Metrics)
	}
	return &Server{
		lc:        opts.LocalClient,
		state:     state,
		self:      opts.LocalSource,
		links:     opts.UILinks,
		prefix:    opts.routePrefix(),
		rules:     opts.UIRewriteRules,
		authorize: opts.authorize(),
		qcheck:    opts.checkQuery(),
		qtimeout:  opts.QueryTimeout.Duration(),
		logf:      opts.logf(),
		dbs:       dbs,
	}, nil
}

// SetDB adds or replaces the database associated with the specified source in
// s with the given open db and options. See [SetSource].
func (s *Server) SetDB(source string, db *sql.DB, opts *DBOptions) bool {
	return s.SetSource(source, sqlDB{DB: db}, opts)
}

// SetSource adds or replaces the database associated with the specified source
// in s with the given open db and options.
//
// If a database was already open for the given source, its value is replaced,
// the old database handle is closed, and SetDB reports true.
//
// If no database was already open for the given source, a new source is added
// and SetDB reports false.
func (s *Server) SetSource(source string, db Queryable, opts *DBOptions) bool {
	if db == nil {
		panic("new database is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.dbs {
		if src := u.Get(); src.Source() == source {
			src.swap(db, opts)
			return true
		}
	}
	s.dbs = append(s.dbs, setec.StaticUpdater(&dbHandle{
		db:    db,
		src:   source,
		label: opts.label(),
		named: opts.namedQueries(),
	}))
	return false
}

// Close closes all the database handles held by s and returns the join of
// their errors.
func (s *Server) Close() error {
	dbs := s.getHandles()
	errs := make([]error, len(dbs))
	for i, db := range dbs {
		errs[i] = db.close()
	}
	return errors.Join(errs...)
}

// NewMux constructs an HTTP router for the service.
func (s *Server) NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle(s.prefix+"/", http.StripPrefix(s.prefix, http.HandlerFunc(s.serveUI)))

	// N.B. We have to strip the prefix back off for the static files, since the
	// embedded FS thinks it is rooted at "/".
	mux.Handle(s.prefix+"/static/", http.StripPrefix(s.prefix, http.FileServer(http.FS(staticFS))))
	return mux
}

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q, err := s.qcheck(Query{
		Source: r.FormValue("src"),
		Query:  strings.TrimSpace(r.FormValue("q")),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if q.Source == "" {
		dbs := s.getHandles()
		if len(dbs) != 0 {
			q.Source = dbs[0].Source() // default to the first source
		}
	}

	caller, isAuthorized := s.checkAuth(w, r, q.Source, q.Query)
	if !isAuthorized {
		authErrorCount.Add(1)
		return
	}

	switch r.URL.Path {
	case "/":
		htmlRequestCount.Add(1)
		err = s.serveUIInternal(w, r, caller, q)
	case "/csv":
		csvRequestCount.Add(1)
		err = s.serveCSVInternal(w, r, caller, q)
	case "/json":
		jsonRequestCount.Add(1)
		err = s.serveJSONInternal(w, r, caller, q)
	case "/meta":
		metaRequestCount.Add(1)
		err = s.serveMetaInternal(w, r)
	default:
		badRequestErrorCount.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		code := errorCode(err)
		if code == http.StatusFound {
			http.Redirect(w, r, r.URL.String(), code)
			return
		} else if code >= 400 && code < 500 {
			badRequestErrorCount.Add(1)
		} else {
			internalErrorCount.Add(1)
		}
		http.Error(w, err.Error(), errorCode(err))
		return
	}
}

// serveUIInternal handles the root GET "/" route.
func (s *Server) serveUIInternal(w http.ResponseWriter, r *http.Request, caller string, q Query) error {
	http.SetCookie(w, siteAccessCookie)
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.Header().Set("X-Frame-Options", "DENY")

	// If a non-empty query is present, require either a site access cookie or a
	// no-browsers header.
	if q.Query != "" && !requestHasSecureHeader(r) && !requestHasSiteAccess(r) {
		return statusErrorf(http.StatusFound, "access cookie not found (redirecting)")
	}

	// Get user information if available
	var userInfo *apitype.WhoIsResponse
	if s.lc != nil {
		var err error
		userInfo, err = s.lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			s.logf("[tailsql] Failed to get user info: %v", err)
		}
	}

	w.Header().Set("Content-Type", "text/html")
	data := &uiData{
		Query:       q.Query,
		Source:      q.Source,
		Sources:     s.getHandles(),
		Links:       s.links,
		RoutePrefix: s.prefix,
		UserInfo:    userInfo,
	}

	// Fetch recent queries if local state is enabled
	if s.state != nil {
		// Use a retry loop for handling SQLite busy errors
		const maxRetries = 3
		var summaryData *QuerySummary
		var queryLogData *dbResult

		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				time.Sleep(getBackoffDelay(attempt))
			}

			// First get summary information
			summaryRows, err := s.state.Query(r.Context(), `
				WITH recent_window AS (
					SELECT MIN(timestamp) as first_query,
						   MAX(timestamp) as last_query,
						   COUNT(DISTINCT query_id) as unique_queries
					FROM raw_query_log
					WHERE timestamp >= datetime('now', '-7 days')
				)
				SELECT unique_queries,
					   CAST((julianday('now') - julianday(first_query)) * 24 as INTEGER) as hours_span
				FROM recent_window`)

			if err != nil {
				if strings.Contains(err.Error(), "database is locked") {
					s.logf("[tailsql] Database locked, retrying summary fetch (attempt %d): %v", attempt+1, err)
					continue
				}
				s.logf("[tailsql] Failed to fetch query summary: %v", err)
				break
			}

			if summaryRows.Next() {
				var uniqueQueries int
				var hoursSpan int
				if err := summaryRows.Scan(&uniqueQueries, &hoursSpan); err == nil {
					summaryData = &QuerySummary{
						UniqueQueries: uniqueQueries,
						HoursSpan:     hoursSpan,
					}
				}
			}
			summaryRows.Close()

			// Then get the detailed query information
			rows, err := s.state.Query(r.Context(), `
				WITH ranked_queries AS (
					SELECT q.query,
						   l.timestamp,
						   l.author,
						   l.elapsed,
						   ROW_NUMBER() OVER (PARTITION BY q.query ORDER BY l.timestamp DESC) as rn
					FROM raw_query_log l
					JOIN queries q ON l.query_id = q.query_id
					WHERE l.timestamp >= datetime('now', '-7 days')
				),
				latest_usage AS (
					SELECT query,
						   timestamp as last_used,
						   author as last_author,
						   elapsed as last_elapsed,
						   (SELECT COUNT(*) 
							FROM raw_query_log l2 
							JOIN queries q2 ON l2.query_id = q2.query_id 
							WHERE q2.query = rq.query) as times_used
					FROM ranked_queries rq
					WHERE rn = 1
				)
				SELECT query, 
					   datetime(last_used), 
					   times_used, 
					   last_author,
					   last_elapsed / 1000000.0 as last_elapsed_seconds
				FROM latest_usage
				ORDER BY last_used DESC
				LIMIT ?`, maxRecentQueries)

			if err != nil {
				if strings.Contains(err.Error(), "database is locked") {
					s.logf("[tailsql] Database locked, retrying query log fetch (attempt %d): %v", attempt+1, err)
					continue
				}
				s.logf("[tailsql] Failed to fetch query log: %v", err)
				break
			}

			// Convert the rows to a dbResult
			cols, err := rows.Columns()
			if err != nil {
				s.logf("[tailsql] Failed to get columns: %v", err)
				rows.Close()
				break
			}

			var result dbResult
			result.Columns = cols

			// Limit the number of recent queries to prevent unbounded memory growth
			result.Rows = make([][]any, 0, maxRecentQueries)

			for rows.Next() {
				if len(result.Rows) >= maxRecentQueries {
					break
				}
				if err := r.Context().Err(); err != nil {
					s.logf("[tailsql] Context cancelled while scanning rows: %v", err)
					break
				}
				vals := make([]any, len(cols))
				ptrs := make([]any, len(cols))
				for i := range vals {
					ptrs[i] = &vals[i]
				}
				if err := rows.Scan(ptrs...); err != nil {
					s.logf("[tailsql] Failed to scan row: %v", err)
					continue
				}
				result.Rows = append(result.Rows, vals)
			}

			if err := rows.Err(); err != nil {
				s.logf("[tailsql] Error iterating rows: %v", err)
			} else {
				result.NumRows = len(result.Rows)
				queryLogData = &result
			}
			rows.Close()

			// If we got here, both queries succeeded
			break
		}

		// Set the data we retrieved (if any)
		if summaryData != nil {
			data.QuerySummary = summaryData
		}
		if queryLogData != nil {
			data.QueryLog = queryLogData
		}
	}

	out, err := s.queryContext(r.Context(), caller, q)
	if errors.Is(err, errTooManyRows) {
		out.More = true
	} else if err != nil {
		queryErrorCount.Add(1)
		msg := err.Error()
		data.Error = &msg
		return ui.Execute(w, data)
	}

	// Don't send too many rows to the UI, the DOM only has one gerbil on its
	// wheel. Note we leave NumRows alone, so it can be used to report the real
	// number of results the query returned.
	const maxUIRows = 500
	if out != nil && out.NumRows > maxUIRows {
		out.Rows = out.Rows[:maxUIRows]
		out.Trunc = true
	}
	data.Output = out.uiOutput("(null)", s.rules)
	return ui.Execute(w, data)
}

// serveCSVInternal handles the GET /csv route.
func (s *Server) serveCSVInternal(w http.ResponseWriter, r *http.Request, caller string, q Query) error {
	if q.Query == "" {
		return statusErrorf(http.StatusBadRequest, "no query provided")
	}

	// Require either a site access cookie or a no-browsers header.
	if !requestHasSecureHeader(r) && !requestHasSiteAccess(r) {
		return statusErrorf(http.StatusForbidden, "query access denied")
	}

	out, err := s.queryContext(r.Context(), caller, q)
	if errors.Is(err, errTooManyRows) {
		// fall through to serve what we got
	} else if err != nil {
		queryErrorCount.Add(1)
		return err
	}

	return writeResponse(w, r, "text/csv", func(w io.Writer) error {
		cw := csv.NewWriter(w)
		cw.WriteAll(out.csvOutput())
		cw.Flush()
		return cw.Error()
	})
}

// serveJSONInternal handles the GET /json route.
func (s *Server) serveJSONInternal(w http.ResponseWriter, r *http.Request, caller string, q Query) error {
	if q.Query == "" {
		return statusErrorf(http.StatusBadRequest, "no query provided")
	}
	if !requestHasSecureHeader(r) {
		return statusErrorf(http.StatusForbidden, "query access denied")
	}

	out, err := s.queryContextJSON(r.Context(), caller, q)
	if err != nil {
		queryErrorCount.Add(1)
		return err
	}

	return writeResponse(w, r, "application/json", func(w io.Writer) error {
		enc := json.NewEncoder(w)
		for _, row := range out {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return nil
	})
}

// serveMetaInternal handles the GET /meta route.
func (s *Server) serveMetaInternal(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	opts := &Options{UILinks: s.links, QueryTimeout: Duration(s.qtimeout)}
	for _, h := range s.getHandles() {
		opts.Sources = append(opts.Sources, DBSpec{
			Source: h.Source(),
			Label:  h.Label(),
			Named:  h.Named(),

			// N.B. Don't report the URL or the KeyFile location.
		})
	}
	return json.NewEncoder(w).Encode(struct {
		Meta *Options `json:"meta"`
	}{Meta: opts})
}

// errTooManyRows is a sentinel error reported by queryContextAny when a
// sensible bound on the size of the result set is exceeded.
var errTooManyRows = errors.New("too many rows")

// queryContextAny executes query using the database handle identified by src.
// The results have whatever types were assigned by the database scanner.
//
// If the number of rows exceeds a sensible limit, it reports errTooManyRows.
// In that case, the result set is still valid, and contains the results that
// were read up to that point.
func (s *Server) queryContext(ctx context.Context, caller string, q Query) (*dbResult, error) {
	if q.Query == "" {
		return nil, nil
	}

	// As a special case, treat a query prefixed with "meta:" as a meta-query to
	// be answered regardless of source.
	if strings.HasPrefix(q.Query, "meta:") {
		return s.queryMeta(ctx, q.Query)
	}

	h := s.dbHandleForSource(q.Source)
	if h == nil {
		return nil, statusErrorf(http.StatusBadRequest, "unknown source %q", q.Source)
	}
	// Verify that the query does not contain statements we should not ask the
	// database to execute.
	if err := checkQuerySyntax(q.Query); err != nil {
		return nil, statusErrorf(http.StatusBadRequest, "invalid query: %w", err)
	}

	const maxRowsPerQuery = 10000

	if s.qtimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.qtimeout)
		defer cancel()
	}

	return runQuery(ctx, h,
		func(fctx context.Context, db Queryable) (_ *dbResult, err error) {
			start := time.Now()
			var out dbResult
			defer func() {
				out.Elapsed = time.Since(start)
				s.logf("[tailsql] query who=%q src=%q query=%q elapsed=%v err=%v",
					caller, q.Source, q.Query, out.Elapsed.Round(time.Millisecond), err)

				// Record successful queries in the persistent log.  But don't log
				// queries to the state database itself.
				if err == nil && q.Source != s.self && s.state != nil {
					// Use a retry loop for handling SQLite busy errors
					const maxRetries = 3
					var logErr error

					for attempt := 0; attempt < maxRetries; attempt++ {
						if attempt > 0 {
							time.Sleep(getBackoffDelay(attempt))
						}

						if err := s.state.LogQuery(ctx, caller, q, out.Elapsed); err != nil {
							if strings.Contains(err.Error(), "database is locked") ||
								strings.Contains(err.Error(), "cannot start a transaction within a transaction") {
								s.logf("[tailsql] Database busy, retrying query log (attempt %d): %v", attempt+1, err)
								continue
							}
							logErr = err
							break
						}
						// Successfully logged
						logErr = nil
						break
					}

					if logErr != nil {
						s.logf("[tailsql] WARNING: Error logging query: %v", logErr)
					}
				}
			}()

			// Check for a named query.
			if name, ok := strings.CutPrefix(q.Query, "named:"); ok {
				real, ok := lookupNamedQuery(fctx, name)
				if !ok {
					return nil, statusErrorf(http.StatusBadRequest, "named query %q not recognized", name)
				}
				s.logf("[tailsql] resolved named query %q to %#q", name, real)
				q.Query = real
			}

			rows, err := db.Query(fctx, q.Query)
			if err != nil {
				return nil, err
			}
			defer rows.Close()

			cols, err := rows.Columns()
			if err != nil {
				return nil, fmt.Errorf("listing column names: %w", err)
			}
			out.Columns = cols

			var tooMany bool
			for rows.Next() && !tooMany {
				if len(out.Rows) == maxRowsPerQuery {
					tooMany = true
					break
				} else if fctx.Err() != nil {
					return nil, fmt.Errorf("scanning row: %w", fctx.Err())
				}
				vals := make([]any, len(cols))
				vptr := make([]any, len(cols))
				for i := range cols {
					vptr[i] = &vals[i]
				}
				if err := rows.Scan(vptr...); err != nil {
					return nil, fmt.Errorf("scanning row: %w", err)
				}
				out.Rows = append(out.Rows, vals)
			}
			if err := rows.Err(); err != nil {
				return nil, fmt.Errorf("scanning rows: %w", err)
			}
			out.NumRows = len(out.Rows)

			if tooMany {
				return &out, errTooManyRows
			}
			return &out, nil
		})
}

// queryMeta handles meta-queries for internal state.
func (s *Server) queryMeta(ctx context.Context, metaQuery string) (*dbResult, error) {
	switch metaQuery {
	case "meta:named":
		// Report all the named queries
		res := &dbResult{
			Columns: []string{"source", "label", "queryName", "sql"},
		}
		for _, h := range s.getHandles() {
			source, label := h.Source(), h.Label()
			for name, sql := range h.Named() {
				res.Rows = append(res.Rows, []any{source, label, name, sql})
			}
		}
		res.NumRows = len(res.Rows)
		return res, nil
	default:
		return nil, statusErrorf(http.StatusBadRequest, "unknown meta-query %q", metaQuery)
	}
}

// queryContextJSON calls s.queryContextAny and, if it succeeds, converts its
// results into values suitable for JSON encoding.
func (s *Server) queryContextJSON(ctx context.Context, caller string, q Query) ([]jsonRow, error) {
	if q.Query == "" {
		return nil, nil
	}

	out, err := s.queryContext(ctx, caller, q)
	if errors.Is(err, errTooManyRows) {
		// fall through to serve what we got
	} else if err != nil {
		return nil, err
	}
	rows := make([]jsonRow, len(out.Rows))
	for i, row := range out.Rows {
		jr := make(jsonRow, len(row))
		for j, col := range row {
			// Treat human-readable byte slices as strings.
			if b, ok := col.([]byte); ok && utf8.Valid(b) {
				col = string(b)
			}
			jr[out.Columns[j]] = col
		}
		rows[i] = jr
	}
	return rows, nil
}

// dbHandleForSource returns the database handle matching the specified src, or
// nil if no matching handle is found.
func (s *Server) dbHandleForSource(src string) *dbHandle {
	for _, h := range s.getHandles() {
		if h.Source() == src {
			return h
		}
	}
	return nil
}

// checkAuth reports the name of the caller and whether they have access to the
// given source.  If the caller does not have access, checkAuth logs an error
// to w and returns false.  The reported caller name will be "" if no caller
// can be identified.
func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request, src, query string) (string, bool) {
	// If there is no local client, allow everything.
	if s.lc == nil {
		return "", true
	}
	whois, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return "", false
	} else if whois == nil {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return "", false
	}
	var caller string
	if whois.Node.IsTagged() {
		caller = whois.Node.Name
	} else {
		caller = whois.UserProfile.LoginName
	}

	// If the caller wants the UI and didn't send a query, allow it.
	// The source does not matter when there is no query.
	if r.URL.Path == "/" && query == "" {
		return caller, true
	}
	if err := s.authorize(src, whois); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return caller, false
	}
	return caller, true
}

// getHandles returns the current slice of database handles.  THe caller must
// not mutate the slice, but it is safe to read it without a lock.
func (s *Server) getHandles() []*dbHandle {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*dbHandle, len(s.dbs))

	// Check for pending updates.
	for i, u := range s.dbs {
		out[i] = u.Get()
		out[i].tryUpdate()
	}

	// It is safe to return the slice because we never remove any elements, new
	// data are only ever appended to the end.
	return out
}
