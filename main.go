package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/likexian/whois"
	"github.com/pixelbender/go-traceroute/traceroute"
	"github.com/tatsushid/go-fastping"
	context2 "golang.org/x/net/context"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type users struct {
	ip              string
	detail          string
	info_ip         string
	created_at      string
	updated_at      string
	user_agent_info string
	results         string
}

func getPort(portEnvVar, defaultPort string) string {
	p := os.Getenv(portEnvVar)
	if p != "" {
		return ":" + p
	}
	return ":" + defaultPort
}

func main() {
	http.HandleFunc("/index", HomeHandler)
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/pinging", PingHandler)
	http.HandleFunc("/pingSelect", Pinging)
	http.HandleFunc("/portCheck", PortCheckHandler)
	http.HandleFunc("/selected", PortStaf)
	http.HandleFunc("/dnsLookup", DNSLookupHandler)
	http.HandleFunc("/dnsSelect", DNSLookupStaff)
	http.HandleFunc("/reverseDnsLookup", ReverseDNSLookupHandler)
	http.HandleFunc("/reverseDnsSelect", ReverseDNSLookupStaff)
	http.HandleFunc("/traceroute", TracerouteHandler)
	http.HandleFunc("/tracerouteSelect", TracerouteStaff)
	http.HandleFunc("/whoIs", WhoisHandler)
	http.HandleFunc("/whoisSelect", WhoisStaff)

	httpsPort := getPort("HTTPS_PORT", "443")
	certFile := "cert.pem"
	keyFile := "key.pem"
	go func() {
		log.Fatal(http.ListenAndServeTLS(httpsPort, certFile, keyFile, nil))
	}()
	httpPort := getPort("HTTP_PORT", "80")
	go func() {
		log.Fatal(http.ListenAndServe(httpPort, nil))
	}()

	select {}

}

const (
	username = "user1"
	password = "123"
	hostname = "127.0.0.1:3306"
	dbname   = "GoWebTestDb"
)

func dsn(dbName string) string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s", username, password, hostname, dbName)
}
func DataBaseConnect() (*sql.DB, error) {

	db, err := sql.Open("mysql", dsn(""))
	if err != nil {
		log.Printf("Error %s when opening DB\n", err)
		return nil, err
	}

	ctx, cancelfunc := context2.WithTimeout(context2.Background(), 5*time.Second)
	defer cancelfunc()

	db, err = sql.Open("mysql", dsn(dbname))

	if err != nil {
		log.Printf("Error %s when opening DB", err)
		return nil, err
	}
	//defer db.Close()

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(time.Minute * 5)

	ctx, cancelfunc = context2.WithTimeout(context2.Background(), 5*time.Second)
	defer cancelfunc()
	err = db.PingContext(ctx)
	if err != nil {
		log.Printf("Errors %s pinging DB", err)
		return nil, err
	}
	log.Printf("Connected to DB %s successfully\n", dbname)
	return db, nil
}

func createUserTable(db *sql.DB) error {
	query := `CREATE TABLE IF NOT EXISTS 
    	users
		(user_id int primary key auto_increment,
		user_ip varchar(255),
    	info_ip varchar(200),
     	user_detail text, 
    	created_at  datetime default CURRENT_TIMESTAMP,
    	updated_at  datetime default CURRENT_TIMESTAMP)`
	ctx, cancelfunc := context2.WithTimeout(context2.Background(), 5*time.Second)
	defer cancelfunc()
	res, err := db.ExecContext(ctx, query)
	if err != nil {
		log.Printf("Error %s when creating product table", err)
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		log.Printf("Error %s when getting rows affected", err)
		return err
	}
	log.Printf("Rows affected when creating table: %d", rows)

	return nil
}

func insertTable(db *sql.DB, u users) error {

	query := "Insert INTO users(user_ip, user_detail,info_ip,created_at,updated_at,user_agent_info,user_results) values (?,?,?,?,?,?,?)"
	ctx, cancelfunc := context2.WithTimeout(context2.Background(), 5*time.Second)
	defer cancelfunc()
	stmt, err := db.PrepareContext(ctx, query)
	if err != nil {
		log.Printf("Error %s when preparing SQL statement", err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, u.ip, u.detail, u.info_ip, u.created_at, u.updated_at, u.user_agent_info, u.results)
	if err != nil {
		log.Printf("Error %s when inserting row into products table", err)
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		log.Printf("Error %s when finding rows affected", err)
		return err
	}
	log.Printf("%d products created ", rows)
	return nil
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	localIP := GetOutboundIP(r)
	data := map[string]interface{}{
		"localIp": localIP,
	}
	log.Println("local ip is: ", localIP)
	/*
		db, err := DataBaseConnect()
		if err != nil {
			http.Error(w, "Error connecting to the database", http.StatusInternalServerError)
			return
		}

		err = insertTable(db, users{ip: localIP})
		if err != nil {
			http.Error(w, "Error inserting data to the database", http.StatusInternalServerError)
			return
		}
	*/
	renderTemplate(w, "index.html", data)
}

func GetOutboundIP(r *http.Request) string {

	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}

	return IPAddress
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "pinging.html", nil)
}
func Pinging(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ip := r.Form.Get("ip")

	p := fastping.NewPinger()
	ra, err := net.ResolveIPAddr("ip4:icmp", ip)
	if err != nil {
		log.Println("ResolveIPAddr error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	p.AddIPAddr(ra)

	type PingResult struct {
		IP  string
		RTT time.Duration
		TTL int
	}

	var pingResults []PingResult

	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		pingResults = append(pingResults, PingResult{
			IP:  addr.String(),
			RTT: rtt,
		})
	}

	err = p.Run()
	if err != nil {
		log.Println("Pinger error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var bytesOfData []string

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Println("icmp.ListenPacket error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer c.Close()

	for _, result := range pingResults {
		// Oluşturulan ICMP paketi için sekans numarası eklemek gerekmektedir
		seq := 1
		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  seq,
				Data: []byte(""),
			},
		}

		b, err := m.Marshal(nil)
		if err != nil {
			log.Println("icmp.Message.Marshal error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		start := time.Now()
		_, err = c.WriteTo(b, &net.IPAddr{IP: net.ParseIP(result.IP)})
		if err != nil {
			log.Println("icmp.WriteTo error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		reply := make([]byte, 1500)
		err = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			log.Println("SetReadDeadline error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		_, _, err = c.ReadFrom(reply)
		if err != nil {
			// ICMP paketi alınamazsa TTL değeri -1 olarak atanır.
			bytesOfData = append(bytesOfData, fmt.Sprintf("IP: %s, TTL: %d, RTT: %v", result.IP, -1, time.Since(start)))
			continue
		}

		// ICMP paketi alındıysa TTL değeri elde edilir.
		rm, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), reply)
		if err != nil {
			log.Println("icmp.ParseMessage error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		rtt := time.Since(start)
		ttl := -1

		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded:
			// TTL değeri Time Exceeded ICMP mesajından elde edilir.
			ttl = int(reply[36])
		case ipv4.ICMPTypeEchoReply:
			// TTL değeri Echo Reply ICMP mesajından elde edilir.
			ttl = int(reply[8])
		}

		bytesOfData = append(bytesOfData, fmt.Sprintf("IP: %s, TTL: %d, RTT: %v", result.IP, ttl, rtt))
	}
	start := time.Now()
	timeElapsed := time.Since(start)
	timeElapsedStr := timeElapsed.String()

	var resultsStr string
	for _, result := range bytesOfData {
		resultsStr += result + "\n"
	}
	packetLoss := 100.0 - (float64(len(pingResults)) / float64(4) * 100)
	packetsReceived := 0
	for _, result := range pingResults {
		if result.TTL != -1 {
			packetsReceived++
		}
	}
	data := map[string]interface{}{
		"ip":                 ip,
		"pingResults":        pingResults,
		"packetsTransmitted": len(pingResults), //gönderilen ping isteklerinin top say/kaç adet ping isteği gönderilmiş
		"packetsReceived":    packetsReceived,  // alınan ping yanıtlarının top sayısı/ "	"	"		"	yanıt verilmiş
		"packetLoss":         fmt.Sprintf("%.2f%%", packetLoss),
		"time":               timeElapsedStr, // Burada zaman değeri göstermek için gerçek bir veri kullanabilirsiniz.
		"bytesOfData":        bytesOfData,
	}

	db, err := DataBaseConnect()
	if err != nil {
		http.Error(w, "Error connecting to the database", http.StatusInternalServerError)
		return
	}
	userAgent := r.UserAgent()
	currentTime := getCurrentDateTime()
	currentTimeStr := currentTime.Format("2006-01-02 15:04:05")
	fmt.Printf("%V", currentTimeStr)
	userIp := GetOutboundIP(r)
	err = insertTable(db, users{
		ip:              userIp,
		detail:          "Pinging",
		info_ip:         ip,
		updated_at:      currentTimeStr,
		created_at:      currentTimeStr,
		user_agent_info: userAgent,
		results:         resultsStr,
	})
	if err != nil {
		http.Error(w, "Error inserting data to the database", http.StatusInternalServerError)
		return
	}
	renderTemplate(w, "pinging.html", data)

}
func getCurrentDateTime() time.Time {
	currentTime := time.Now()
	year, month, day := currentTime.Date()
	hour, minute, second := currentTime.Clock()
	return time.Date(year, month, day, hour, minute, second, 0, currentTime.Location())
}

func PortCheckHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "portCheck.html", nil)
}
func IsPortOpen(ip, port string) bool {
	conn, err := net.DialTimeout("tcp", ip+":"+port, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func PortStaf(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ip := r.Form.Get("ip")
	port := r.Form.Get("port")

	data := map[string]interface{}{}
	data["ip"] = ip
	data["port"] = port
	var result string
	log.Printf("IP: %s Port: %s", ip, port)

	if IsPortOpen(ip, port) {
		data["portStatus"] = "Port is open"
		result = "Port is open"
		log.Print("Port is open")
	} else {
		data["portStatus"] = "Port is closed"
		result = "Port is open"
		log.Print("Port is closed")
	}

	t, err := template.ParseFiles("portCheck.html") //parse the html file homepage.html
	if err != nil {                                 // if there is an error
		log.Print("template parsing error: ", err) // log it
	}

	err = t.Execute(w, data) //execute the template and pass it the HomePageVars struct to fill in the gaps
	if err != nil {          // if there is an error
		log.Print("template executing error: ", err) //log it
	}
	db, err := DataBaseConnect()
	if err != nil {
		http.Error(w, "Error connecting to the database", http.StatusInternalServerError)
		return
	}

	userAgent := r.UserAgent()
	currentTime := getCurrentDateTime()
	currentTimeStr := currentTime.Format("2006-01-02 15:04:05")
	user_ip := GetOutboundIP(r)
	err = insertTable(db, users{
		ip:              user_ip,
		detail:          "PortCheck",
		info_ip:         ip + " port is: " + port,
		updated_at:      currentTimeStr,
		created_at:      currentTimeStr,
		user_agent_info: userAgent,
		results:         result,
	})
}
func DNSLookupHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "dnsLookup.html", nil)
}
func DNSLookupStaff(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	domain := r.Form.Get("domain")

	results, err := dnsLookup(domain)
	if err != nil {
		fmt.Println("Error: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"domain":  domain,
		"results": results,
	}

	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	db, err := DataBaseConnect()
	if err != nil {
		http.Error(w, "Error connecting to the database", http.StatusInternalServerError)
		return
	}
	userAgent := r.UserAgent()
	currentTime := getCurrentDateTime()
	currentTimeStr := currentTime.Format("2006-01-02 15:04:05")
	user_ip := GetOutboundIP(r)
	err = insertTable(db, users{
		ip:              user_ip,
		detail:          "DNSLookUp",
		info_ip:         domain,
		updated_at:      currentTimeStr,
		created_at:      currentTimeStr,
		user_agent_info: userAgent,
		results:         results,
	})
	renderTemplate(w, "dnsLookup.html", data)
}

func dnsLookup(domain string) (string, error) {

	addrs, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}

	result := ""
	for _, addr := range addrs {
		result += fmt.Sprintf("Address: %s#53\n", addr.String())
	}

	txts, err := net.LookupTXT(domain)
	if err == nil && len(txts) > 0 {
		result += fmt.Sprintf("TXT: %s\n", txts)
	}

	cname, err := net.LookupCNAME(domain)
	if err == nil {
		result += fmt.Sprintf("Aliases: %s\n", cname)
	}

	ips, err := net.LookupIP(domain)
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			result += fmt.Sprintf("%s has address %s\n", domain, ip.String())
		}
	}

	return result, nil
}
func ReverseDNSLookupHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "reverseDnsLookup.html", nil)
}
func ReverseDNSLookupStaff(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ip := r.Form.Get("ip")

	data := map[string]interface{}{}
	data["ip"] = ip

	names, err := net.LookupAddr(ip)
	if err != nil {
		data["error"] = "DNS lookup failed: " + err.Error()
	} else {
		data["results"] = formatDNSResults(names)
	}

	t, err := template.ParseFiles("reverseDnsLookup.html")
	if err != nil {
		log.Print("template parsing error: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Print("template executing error: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	db, err := DataBaseConnect()
	if err != nil {
		http.Error(w, "Error connecting to the database", http.StatusInternalServerError)
		return
	}
	userAgent := r.UserAgent()
	currentTime := getCurrentDateTime()
	currentTimeStr := currentTime.Format("2006-01-02 15:04:05")
	user_ip := GetOutboundIP(r)
	err = insertTable(db, users{
		ip:              user_ip,
		detail:          "Reverse DNSLookUp",
		info_ip:         ip,
		updated_at:      currentTimeStr,
		created_at:      currentTimeStr,
		user_agent_info: userAgent,
		results:         formatDNSResults(names),
	})
}
func formatDNSResults(names []string) string {
	var result string
	if len(names) > 0 {
		result = fmt.Sprintf("Using domain server:\nName: %s\nAddress: %s#53\nAliases: %s", names[0], names[0], names[0])
	} else {
		result = "No DNS records found for the given IP."
	}
	return result
}

func TracerouteHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "traceroute.html", nil)
}

func TracerouteStaff(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ip := r.Form.Get("ip")

	if !isValidIP(ip) {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	// Traceroute işlemini gerçekleştir ve sonuçları data map'ine ekle
	hops, err := traceroute.Trace(net.ParseIP(ip))
	if err != nil {
		log.Println("Traceroute error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var traceResults []map[string]interface{}

	for _, hop := range hops {
		for _, node := range hop.Nodes {
			//log.Printf("%d. %v %v", hop.Distance, node.IP, node.RTT)
			hopData := map[string]interface{}{
				"Distance": hop.Distance,
				"IP":       node.IP,
				"RTT":      node.RTT,
			}
			traceResults = append(traceResults, hopData)

		}
	}
	// TraceResults dizisini JSON formatına dönüştür
	traceResultsJSON, err := json.Marshal(traceResults)
	if err != nil {
		log.Println("JSON marshaling error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	db, err := DataBaseConnect()
	if err != nil {
		http.Error(w, "Error connecting to the database", http.StatusInternalServerError)
		return
	}
	userAgent := r.UserAgent()
	currentTime := getCurrentDateTime()
	currentTimeStr := currentTime.Format("2006-01-02 15:04:05")
	user_ip := GetOutboundIP(r)
	err = insertTable(db, users{
		ip:              user_ip,
		detail:          "Traceroute ",
		info_ip:         ip,
		updated_at:      currentTimeStr,
		created_at:      currentTimeStr,
		user_agent_info: userAgent,
		results:         string(traceResultsJSON), //????????????
	})
	data := map[string]interface{}{
		"ip":           ip,
		"traceResults": traceResults,
	}
	renderTemplate(w, "traceroute.html", data)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func WhoisHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "whoIs.html", nil)
}
func WhoisStaff(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ip := r.Form.Get("ip")

	result, err := whois.Whois(ip)
	if err != nil {
		log.Println("Whois query error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"ip":   ip,
		"resp": result,
	}

	db, err := DataBaseConnect()
	if err != nil {
		http.Error(w, "Error connecting to the database", http.StatusInternalServerError)
		return
	}
	limitedResult := result
	if len(result) > 100 {
		limitedResult = strings.Join(strings.Fields(result)[:100], " ")
	}
	userAgent := r.UserAgent()
	currentTime := getCurrentDateTime()
	currentTimeStr := currentTime.Format("2006-01-02 15:04:05")
	user_ip := GetOutboundIP(r)
	err = insertTable(db, users{
		ip:              user_ip,
		detail:          "WhoIs: ",
		info_ip:         ip,
		updated_at:      currentTimeStr,
		created_at:      currentTimeStr,
		user_agent_info: userAgent,
		results:         limitedResult,
	})
	renderTemplate(w, "whoIs.html", data)
}

func renderTemplate(w http.ResponseWriter, templateFile string, data interface{}) {
	tmpl, err := template.ParseFiles(templateFile)
	if err != nil {
		log.Println("Template parsing error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
