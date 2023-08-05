package main

import (
	"github.com/pixelbender/go-traceroute/traceroute"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
)

func getPort1(portEnvVar, defaultPort string) string {
	p := os.Getenv(portEnvVar)
	if p != "" {
		return ":" + p
	}
	return ":" + defaultPort
}
func main() {
	http.HandleFunc("/", VerificationForHtml1)

	http.HandleFunc("/traceroute", TracerouteHandler1)
	http.HandleFunc("/tracerouteSelect", TracerouteStaff1)

	httpPort := getPort1("HTTP_PORT", "800")
	go func() {
		log.Fatal(http.ListenAndServe(httpPort, nil))

	}()
	httpsPort := getPort1("HTTPS_PORT", "100")
	certFile := "cert.pem"
	keyFile := "key.pem"

	go func() {
		log.Fatal(http.ListenAndServeTLS(httpsPort, certFile, keyFile, nil))
	}()

	select {}

}

func TracerouteHandler1(w http.ResponseWriter, r *http.Request) {
	renderTemplate1(w, "traceroute.html", nil)
}

func TracerouteStaff1(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		log.Println("Failed to parse form:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	ip := r.Form.Get("ip")
	data := map[string]interface{}{
		"ip": ip,
	}
	hops, err := traceroute.Trace(net.ParseIP(ip))
	if err != nil {
		log.Fatal(err)
	}
	for _, h := range hops {
		for _, n := range h.Nodes {
			log.Printf("%d. %v %v", h.Distance, n.IP, n.RTT)
			data["Distance"] = h.Distance
			data["IP"] = n.IP
			data["RTT"] = n.RTT
		}
	}

	renderTemplate1(w, "traceroute.html", data)
}

func renderTemplate1(w http.ResponseWriter, templateFile string, data interface{}) {
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
func VerificationForHtml1(w http.ResponseWriter, r *http.Request) {

	t, err := template.ParseFiles("traceroute.html") //parse the html file homepage.html
	if err != nil {
		log.Print("template parsing error: ", err)
	}

	err = t.Execute(w, nil) //execute the template and pass it the HomePageVars struct to fill in the gaps
	if err != nil {
		log.Print("template executing error: ", err)
	}

}
