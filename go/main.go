package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/go-martini/martini"
	_ "github.com/go-sql-driver/mysql"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessions"
	"github.com/sonots/go-sql_metrics"
	"net/http"
	"net/http/pprof"
	"strconv"
	//"sync"
	//_ "sync/atomic"
	"time"
)

var _db *sql.DB
var db *sql_metrics.DB
var (
	UserLockThreshold int
	IPBanThreshold    int
)

type BanLog struct {
	failureCount int64
	lastSuccess  time.Time
}

// key is ip
var BanLogs map[string]BanLog = map[string]BanLog{}

type UserBlockLog struct {
	failureCount int64
	lastSuccess  time.Time
}

// key user_id
var UserBlockLogs map[int64]UserBlockLog = map[int64]UserBlockLog{}

func init() {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Local",
		getEnv("ISU4_DB_USER", "root"),
		getEnv("ISU4_DB_PASSWORD", ""),
		getEnv("ISU4_DB_HOST", "localhost"),
		getEnv("ISU4_DB_PORT", "3306"),
		getEnv("ISU4_DB_NAME", "isu4_qualifier"),
	)

	var err error

	_db, err = sql.Open("mysql", dsn)
	db = sql_metrics.WrapDB("mysql", _db)
	if err != nil {
		panic(err)
	}

	UserLockThreshold, err = strconv.Atoi(getEnv("ISU4_USER_LOCK_THRESHOLD", "3"))
	if err != nil {
		panic(err)
	}

	IPBanThreshold, err = strconv.Atoi(getEnv("ISU4_IP_BAN_THRESHOLD", "10"))
	if err != nil {
		panic(err)
	}
}

///////// user.go //////////////////
type User struct {
	ID           int
	Login        string
	PasswordHash string
	Salt         string

	LastLogin *LastLogin
}

type LastLogin struct {
	Login     string
	IP        string
	CreatedAt time.Time
}

func (u *User) getLastLogin() *LastLogin {
	rows, err := db.Query(
		"SELECT login, ip, created_at FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2",
		u.ID,
	)

	if err != nil {
		return nil
	}

	defer rows.Close()
	for rows.Next() {
		u.LastLogin = &LastLogin{}
		err = rows.Scan(&u.LastLogin.Login, &u.LastLogin.IP, &u.LastLogin.CreatedAt)
		if err != nil {
			u.LastLogin = nil
			return nil
		}
	}

	return u.LastLogin
}

//////// db.go //////////////
var (
	ErrBannedIP      = errors.New("Banned IP")
	ErrLockedUser    = errors.New("Locked user")
	ErrUserNotFound  = errors.New("Not found user")
	ErrWrongPassword = errors.New("Wrong password")
)

func createLoginLog(succeeded bool, remoteAddr, login string, user *User) error {
	succ := 0
	if succeeded {
		succ = 1
	}

	var userId sql.NullInt64
	if user != nil {
		userId.Int64 = int64(user.ID)
		userId.Valid = true
	}

	_, err := db.Exec(
		"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
			"VALUES (?,?,?,?,?)",
		time.Now(), userId, login, remoteAddr, succ,
	)

	return err
}

func isLockedUser(user *User) (bool, error) {
	if user == nil {
		return false, nil
	}

	var ni sql.NullInt64
	row := db.QueryRow(
		"SELECT COUNT(1) AS failures FROM login_log WHERE "+
			"user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND "+
			"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
		user.ID, user.ID,
	)
	err := row.Scan(&ni)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return UserLockThreshold <= int(ni.Int64), nil
}

func isBannedIP(ip string) (bool, error) {
	var ni sql.NullInt64
	row := db.QueryRow(
		"SELECT COUNT(1) AS failures FROM login_log WHERE "+
			"ip = ? AND id > IFNULL((select id from login_log where ip = ? AND "+
			"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
		ip, ip,
	)
	err := row.Scan(&ni)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return IPBanThreshold <= int(ni.Int64), nil
}

func attemptLogin(req *http.Request) (*User, error) {
	succeeded := false
	user := &User{}

	loginName := req.PostFormValue("login")
	password := req.PostFormValue("password")

	remoteAddr := req.RemoteAddr
	if xForwardedFor := req.Header.Get("X-Forwarded-For"); len(xForwardedFor) > 0 {
		remoteAddr = xForwardedFor
	}

	defer func() {
		createLoginLog(succeeded, remoteAddr, loginName, user)
	}()

	row := db.QueryRow(
		"SELECT id, login, password_hash, salt FROM users WHERE login = ?",
		loginName,
	)
	err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	switch {
	case err == sql.ErrNoRows:
		user = nil
	case err != nil:
		return nil, err
	}

	if banned, _ := isBannedIP(remoteAddr); banned {
		return nil, ErrBannedIP
	}

	if locked, _ := isLockedUser(user); locked {
		return nil, ErrLockedUser
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.PasswordHash != calcPassHash(password, user.Salt) {
		return nil, ErrWrongPassword
	}

	succeeded = true
	return user, nil
}

func getCurrentUser(userId interface{}) *User {
	user := &User{}
	row := db.QueryRow(
		"SELECT id, login, password_hash, salt FROM users WHERE id = ?",
		userId,
	)
	err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	if err != nil {
		return nil
	}

	return user
}

func bannedIPs() []string {
	ips := []string{}

	rows, err := db.Query(
		"SELECT ip FROM "+
			"(SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) "+
			"AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?",
		IPBanThreshold,
	)

	if err != nil {
		return ips
	}

	defer rows.Close()
	for rows.Next() {
		var ip string

		if err := rows.Scan(&ip); err != nil {
			return ips
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return ips
	}

	rowsB, err := db.Query(
		"SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip",
	)

	if err != nil {
		return ips
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var ip string
		var lastLoginId int

		if err := rows.Scan(&ip, &lastLoginId); err != nil {
			return ips
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id",
			ip, lastLoginId,
		).Scan(&count)

		if err != nil {
			return ips
		}

		if IPBanThreshold <= count {
			ips = append(ips, ip)
		}
	}
	if err := rowsB.Err(); err != nil {
		return ips
	}

	return ips
}

func lockedUsers() []string {
	userIds := []string{}

	rows, err := db.Query(
		"SELECT user_id, login FROM "+
			"(SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) "+
			"AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?",
		UserLockThreshold,
	)

	if err != nil {
		return userIds
	}

	defer rows.Close()
	for rows.Next() {
		var userId int
		var login string

		if err := rows.Scan(&userId, &login); err != nil {
			return userIds
		}
		userIds = append(userIds, login)
	}
	if err := rows.Err(); err != nil {
		return userIds
	}

	rowsB, err := db.Query(
		"SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id",
	)

	if err != nil {
		return userIds
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var userId int
		var login string
		var lastLoginId int

		if err := rowsB.Scan(&userId, &login, &lastLoginId); err != nil {
			return userIds
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id",
			userId, lastLoginId,
		).Scan(&count)

		if err != nil {
			return userIds
		}

		if UserLockThreshold <= count {
			userIds = append(userIds, login)
		}
	}
	if err := rowsB.Err(); err != nil {
		return userIds
	}

	return userIds
}

func main() {
	m := martini.Classic()

	store := sessions.NewCookieStore([]byte("secret-isucon"))
	m.Use(sessions.Sessions("isucon_go_session", store))

	m.Use(martini.Static("../public"))
	m.Use(render.Renderer(render.Options{
		Layout: "layout",
	}))

	m.Get("/", func(r render.Render, session sessions.Session) {
		r.HTML(200, "index", map[string]string{"Flash": getFlash(session, "notice")})
	})

	m.Post("/login", func(req *http.Request, r render.Render, session sessions.Session) {
		user, err := attemptLogin(req)

		notice := ""
		if err != nil || user == nil {
			switch err {
			case ErrBannedIP:
				notice = "You're banned."
			case ErrLockedUser:
				notice = "This account is locked."
			default:
				notice = "Wrong username or password"
			}

			session.Set("notice", notice)
			r.Redirect("/")
			return
		}

		session.Set("user_id", strconv.Itoa(user.ID))
		r.Redirect("/mypage")
	})

	m.Get("/mypage", func(r render.Render, session sessions.Session) {
		currentUser := getCurrentUser(session.Get("user_id"))

		if currentUser == nil {
			session.Set("notice", "You must be logged in")
			r.Redirect("/")
			return
		}

		currentUser.getLastLogin()
		r.HTML(200, "mypage", currentUser)
	})

	m.Get("/report", func(r render.Render) {
		r.JSON(200, map[string][]string{
			"banned_ips":   bannedIPs(),
			"locked_users": lockedUsers(),
		})
	})

	verbose := flag.Bool("verbose", false, "verbose print of metrics")
	disable := flag.Bool("disable", false, "disable metrics")
	if *verbose {
		sql_metrics.Verbose = true
		sql_metrics.Print(-1)
	} else if *disable {
		sql_metrics.Enable = false
	} else {
		sql_metrics.Print(70)
	}

	m.Get("/debug/pprof", pprof.Index)
	m.Get("/debug/pprof/cmdline", pprof.Cmdline)
	m.Get("/debug/pprof/profile", pprof.Profile)
	m.Get("/debug/pprof/symbol", pprof.Symbol)
	m.Post("/debug/pprof/symbol", pprof.Symbol)
	m.Get("/debug/pprof/block", pprof.Handler("block").ServeHTTP)
	m.Get("/debug/pprof/heap", pprof.Handler("heap").ServeHTTP)
	m.Get("/debug/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
	m.Get("/debug/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)

	http.ListenAndServe(":8080", m)
}
