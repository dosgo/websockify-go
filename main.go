package main

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"golang.org/x/net/websocket"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var KeyFile string;
var CertFile string;
func main(){
	var addr string="127.0.0.1:442";
	//接受websocket的路由地址
	http.Handle("/websockify",websocket.Handler(webToTcp))
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("public"))))
	if(KeyFile==""||CertFile==""){
		KeyFile="localhost_server.key"
		CertFile="localhost_server.pem"
		addrs:=strings.Split(addr,":")
		var ip="127.0.0.1";
		if(addrs[0]!="0.0.0.0"||addrs[0]!=""){
			ip=addrs[0];
		}
		_,err:=os.Stat(KeyFile)
		if(err!=nil){
			genCERT("improvement","localhost",ip);
		}
	}
	fmt.Printf("http://"+addr);
	//err :=http.ListenAndServeTLS(addr,CertFile,KeyFile,nil)
	err :=http.ListenAndServe(addr,nil)
	fmt.Printf("err:",err.Error())
}



func webToTcp(ws *websocket.Conn) {
	var host=ws.Request().URL.Query().Get("host");
	var port=ws.Request().URL.Query().Get("port");
	if(host==""||port==""){
		return ;
	}
	conn, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		return
	}
	defer conn.Close()


	go io.Copy(conn, ws)
	io.Copy(ws, conn)
	return
}






/*生成证书,
 */
func genCERT(organization string,host string,ip string) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	privCa, _ := rsa.GenerateKey(rand.Reader, 1024)
	CreateCertificateFile(host+"_ca", ca, privCa, ca, nil)
	server := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	hosts := []string{host, ip}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			server.IPAddresses = append(server.IPAddresses, ip)
		} else {
			server.DNSNames = append(server.DNSNames, h)
		}
	}
	privSer, _ := rsa.GenerateKey(rand.Reader, 1024)
	CreateCertificateFile(host+"_server", server, privSer, ca, privCa)
}

func CreateCertificateFile(name string, cert *x509.Certificate, key *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	priv := key
	pub := &priv.PublicKey
	privPm := priv
	if caKey != nil {
		privPm = caKey
	}
	ca_b, err := x509.CreateCertificate(rand.Reader, cert, caCert, pub, privPm)
	if err != nil {
		log.Println("create failed", err)
		return
	}
	ca_f := name + ".pem"
	var certificate = &pem.Block{Type: "CERTIFICATE",
		Headers: map[string]string{},
		Bytes:   ca_b}
	ca_b64 := pem.EncodeToMemory(certificate)
	ioutil.WriteFile(ca_f, ca_b64, 0777)

	priv_f := name + ".key"
	priv_b := x509.MarshalPKCS1PrivateKey(priv)
	ioutil.WriteFile(priv_f, priv_b, 0777)
	var privateKey = &pem.Block{Type: "PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   priv_b}
	priv_b64 := pem.EncodeToMemory(privateKey)
	ioutil.WriteFile(priv_f, priv_b64, 0777)
}



