package main

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	//"github.com/go-martini/martini"
	_ "github.com/go-sql-driver/mysql"
	//"github.com/martini-contrib/sessions"
	//"github.com/sonots/martini-contrib/render"
	//"net"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	_ "sync/atomic"
	"time"
)

var db *sql.DB
var (
	UserLockThreshold int
	IPBanThreshold    int
)

var indexTmpl = template.Must(template.New("index").ParseFiles("templates/layout.tmpl", "templates/index.tmpl"))
var mypageTmpl = template.Must(template.New("mypage").ParseFiles("templates/layout.tmpl", "templates/mypage.tmpl"))

var mutex = &sync.Mutex{}

// key is ip => failure counts
var BanLogs = map[string]sql.NullInt64{}

// key user_id => failure counts
var UserBlockLogs = map[int]sql.NullInt64{}

var UserIdTable = map[string](*User){}
var UserLoginTable = map[string](*User){}

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

	db, err = sql.Open("mysql", dsn)
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
	Password     string

	LastLogin *LastLogin
}

type LastLogin struct {
	Login     string
	IP        string
	CreatedAt time.Time
}

// key is user_id
var LastLogins = map[int](*LastLogin){}
var LastLoginsSecond = map[int](*LastLogin){}

func (u *User) getLastLogin() *LastLogin {
	if LastLoginsSecond[u.ID] != nil {
		u.LastLogin = LastLoginsSecond[u.ID]
		return LastLoginsSecond[u.ID]
	}

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

func createLoginLog(succeeded bool, remoteAddr, login string, user *User) {
	succ := 0
	if succeeded {
		succ = 1
	}

	var userId sql.NullInt64
	if user != nil {
		userId.Int64 = int64(user.ID)
		userId.Valid = true
	}

	go func() {
		db.Exec(
			"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
				"VALUES (?,?,?,?,?)",
			time.Now(), userId, login, remoteAddr, succ,
		)
	}()
}

func isLockedUser(user *User) (bool, error) {
	if user == nil {
		return false, nil
	}

	if UserBlockLogs[user.ID].Valid {
		//fmt.Printf("%d ", user.ID)
		//fmt.Printf("cached:%d\n", UserBlockLogs[user.ID].Int64)
		return UserLockThreshold <= int(UserBlockLogs[user.ID].Int64), nil
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
		UserBlockLogs[user.ID] = sql.NullInt64{0, true}
		return false, nil
	case err != nil:
		UserBlockLogs[user.ID] = sql.NullInt64{0, true}
		return false, err
	}

	mutex.Lock()
	//fmt.Printf("%d ", user.ID)
	//fmt.Printf("correct:%d\n", ni.Int64)
	if !UserBlockLogs[user.ID].Valid {
		UserBlockLogs[user.ID] = ni
	}
	mutex.Unlock()

	return UserLockThreshold <= int(ni.Int64), nil
}

func isBannedIP(ip string) (bool, error) {
	var ni sql.NullInt64

	if BanLogs[ip].Valid {
		//fmt.Printf("%s cached:%d ", ip, cachedFailure.Int64)
		return IPBanThreshold <= int(BanLogs[ip].Int64), nil
	}

	row := db.QueryRow(
		"SELECT COUNT(1) AS failures FROM login_log WHERE "+
			"ip = ? AND id > IFNULL((select id from login_log where ip = ? AND "+
			"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
		ip, ip,
	)
	err := row.Scan(&ni)

	switch {
	case err == sql.ErrNoRows:
		BanLogs[ip] = sql.NullInt64{0, true}
		return false, nil
	case err != nil:
		BanLogs[ip] = sql.NullInt64{0, true}
		return false, err
	}

	mutex.Lock()
	//fmt.Printf("correct:%d\n", ni.Int64)
	if !BanLogs[ip].Valid {
		BanLogs[ip] = ni
	}
	mutex.Unlock()

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
		if succeeded {
			mutex.Lock()
			BanLogs[remoteAddr] = sql.NullInt64{0, true}
			UserBlockLogs[user.ID] = sql.NullInt64{0, true}
			LastLoginsSecond[user.ID] = LastLogins[user.ID]
			LastLogins[user.ID] = &LastLogin{
				Login:     loginName,
				IP:        remoteAddr,
				CreatedAt: time.Now(),
			}
			mutex.Unlock()
		} else {
			mutex.Lock()
			BanLogs[remoteAddr] = sql.NullInt64{
				Int64: BanLogs[remoteAddr].Int64 + 1,
				Valid: true,
			}
			UserBlockLogs[user.ID] = sql.NullInt64{
				Int64: UserBlockLogs[user.ID].Int64 + 1,
				Valid: true,
			}
			mutex.Unlock()
		}
	}()

	user = UserLoginTable[loginName]
	//fmt.Printf("%s ", loginName)
	//fmt.Println(user)
	//row := db.QueryRow(
	//	"SELECT id, login, password_hash, salt FROM users WHERE login = ?",
	//	loginName,
	//)
	//err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	//switch {
	//case err == sql.ErrNoRows:
	//	user = nil
	//case err != nil:
	//	return nil, err
	//}
	//fmt.Println(user)
	//fmt.Println()

	if banned, _ := isBannedIP(remoteAddr); banned {
		return nil, ErrBannedIP
	}

	if locked, _ := isLockedUser(user); locked {
		return nil, ErrLockedUser
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	//if user.PasswordHash != calcPassHash(password, user.Salt) {
	if user.Password != password {
		return nil, ErrWrongPassword
	}
	succeeded = true
	return user, nil
}

func getCurrentUser(userId interface{}) *User {
	user := &User{}
	//row := db.QueryRow(
	//	"SELECT id, login, password_hash, salt FROM users WHERE id = ?",
	//	userId,
	//)
	//err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	//if err != nil {
	//	return nil
	//}
	user_id, ok := userId.(string)
	//fmt.Print(user_id)
	//fmt.Print(user)
	if !ok {
		return nil
	}
	user = UserIdTable[user_id]
	//fmt.Println(user)

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

func initLoad() {
	rows, err := db.Query(
		"select id, ip from (select * from login_log where succeeded = 1 order by id DESC) A group by ip",
	)

	for rows.Next() {
		var id int
		var ip string
		if err = rows.Scan(&id, &ip); err != nil {
			continue
		}

		// Baned count
		var count sql.NullInt64
		row := db.QueryRow(
			"SELECT COUNT(1) AS failures FROM login_log WHERE id > ? AND succeeded = 0 AND ip = ?",
			id, ip,
		)
		if err = row.Scan(&count); err != nil {
			continue
		}
		BanLogs[ip] = count
	}

	rows, err = db.Query(
		"select id, user_id from (select * from login_log where succeeded = 1 order by id DESC) A group by ip",
	)

	for rows.Next() {
		var id int
		var user_id int
		if err = rows.Scan(&id, &user_id); err != nil {
			continue
		}

		// user block count
		var count sql.NullInt64
		row := db.QueryRow(
			"SELECT COUNT(1) AS failures FROM login_log WHERE id > ? AND succeeded = 0 AND user_id = ?",
			id, user_id,
		)
		if err = row.Scan(&count); err != nil {
			continue
		}
		UserBlockLogs[user_id] = count
	}

	initUserTable()
}

func initUserTable() {
	fmt.Println("InitUserTable")
	rows, _ := db.Query(
		"SELECT id, login, password_hash, salt FROM users",
	)
	for rows.Next() {
		user := &User{}
		_ = rows.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)
		UserIdTable[strconv.Itoa(user.ID)] = user
		UserLoginTable[user.Login] = user
	}

	file, err := os.Open("/home/isucon/sql/dummy_users.tsv")
	if err != nil {
		fmt.Println("can not read")
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		columns := strings.Split(line, "\t")
		user_id := columns[0]
		login := columns[1]
		password := columns[2]
		UserIdTable[user_id].Password = password
		UserLoginTable[login].Password = password
	}
}

var layoutTop = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/stylesheets/bootstrap.min.css">
    <link rel="stylesheet" href="/stylesheets/bootflat.min.css">
    <link rel="stylesheet" href="/stylesheets/isucon-bank.css">
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/"><img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス"></a>
      </h1>
`

var layoutBottom = `
    </div>

  </body>
</html>
`

var indexTop = layoutTop + `<div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>
`

var indexBottom = `
<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>
` + layoutBottom

func main() {
	//cpus := runtime.NumCPU()
	//runtime.GOMAXPROCS(cpus)
	runtime.GOMAXPROCS(32)

	//m := martini.Classic()

	//store := sessions.NewCookieStore([]byte("secret-isucon"))
	//m.Use(sessions.Sessions("isucon_go_session", store))

	http.Handle("/images", http.StripPrefix("/images", http.FileServer(http.Dir("../public"))))
	http.Handle("/stylesheets", http.StripPrefix("/stylesheets", http.FileServer(http.Dir("../public"))))
	//m.Use(martini.Static("../public"))
	//m.Use(render.Renderer(render.Options{
	//	Layout: "layout",
	//}))

	//m.Get("/", func(r render.Render, session sessions.Session) {
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie("notice")
		flash := ""
		if err != nil {
			switch err {
			case http.ErrNoCookie:
				flash = ""
			default:
				fmt.Println("/ get cookie failed")
				flash = ""
			}
		}
		if cookie != nil {
			flash = cookie.Value
		}
		cookie = &http.Cookie{Name: "notice", Value: ""}
		http.SetCookie(w, cookie)
		//indexTmpl.ExecuteTemplate(w, "layout", map[string]string{"Flash": flash})
		flash_message := ""
		if flash != "" {
			flash_message = `<div id="notice-message" class="alert alert-danger" role="alert">` + flash + `</div>`
		}
		fmt.Fprintf(w, "%s%s%s", indexTop, flash_message, indexBottom)
		//r.TopHTML(200, getFlash(session, "notice"))
		//r.HTML(200, "index", map[string]string{"Flash": getFlash(session, "notice")})
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		//m.Post("/login", func(req *http.Request, r render.Render, session sessions.Session) {
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

			cookie := &http.Cookie{Name: "notice", Value: notice}
			http.SetCookie(w, cookie)
			//session.Set("notice", notice)
			http.Redirect(w, req, "/", 302)
			// r.Redirect("/")
			return
		}

		//session.Set("user_id", strconv.Itoa(user.ID))
		cookie := &http.Cookie{Name: "user_id", Value: strconv.Itoa(user.ID)}
		http.SetCookie(w, cookie)

		http.Redirect(w, req, "/mypage", 302)
		// r.Redirect("/mypage")
	})

	//m.Get("/mypage", func(r render.Render, session sessions.Session) {
	http.HandleFunc("/mypage", func(w http.ResponseWriter, req *http.Request) {
		//currentUser := getCurrentUser(session.Get("user_id"))
		cookie, err := req.Cookie("user_id")
		if err != nil {
			fmt.Println("/mypage get cookie failed")
		}
		var currentUser *User
		if cookie != nil {
			currentUser = getCurrentUser(cookie.Value)
		}

		if currentUser == nil {
			// session.Set("notice", "You must be logged in")
			cookie := &http.Cookie{Name: "notice", Value: "You must be logged in"}
			http.SetCookie(w, cookie)
			http.Redirect(w, req, "/", 302)
			return
		}

		currentUser.getLastLogin()
		mypageTmpl.ExecuteTemplate(w, "layout", currentUser)
		// r.HTML(200, "mypage", currentUser)
	})

	http.HandleFunc("/report", func(w http.ResponseWriter, req *http.Request) {
		//m.Get("/report", func(r render.Render) {
		//r.JSON(200, map[string][]string{
		//	"banned_ips":   bannedIPs(),
		//	"locked_users": lockedUsers(),
		//})
		w.Header().Set("Content-Type", "application/json")
		ret := map[string][]string{
			"banned_ips":   bannedIPs(),
			"locked_users": lockedUsers(),
		}
		js, err := json.Marshal(ret)
		if err != nil {
			fmt.Printf("REPORT FAILED!!!!")
		}
		w.Write(js)
	})

	http.HandleFunc("/init", func(w http.ResponseWriter, req *http.Request) {
		fmt.Printf("initLoad started")
		startTime := time.Now()
		initLoad()
		elapsedTime := time.Now().Sub(startTime)
		fmt.Printf("initLoad finished %s", elapsedTime*time.Second)
		return
	})
	initUserTable() // for development

	http.ListenAndServe(":8080", nil)
	// unix domain socket did not improve score, sigh ...
	//proto := "unix"
	//addr := "/tmp/golang-webapp.sock"
	//l, e := net.Listen(proto, addr)
	//if e != nil {
	//	fmt.Println(e)
	//}
	////as the daemon is launched as root, change to permission of the socket to allow non-root to connect
	//if proto == "unix" {
	//	os.Chmod(addr, 0777)
	//}
	//httpSrv := http.Server{Addr: addr, Handler: m}
	//httpSrv.Serve(l)
}
