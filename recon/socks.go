package recon

import (
	"fmt"
	"net/http"
	"net/url"
)

func newHttpClient(proxy int) *http.Client {
	if proxy == 69 {
		return &http.Client{}
	}
	full := fmt.Sprintf("socks5://127.0.0.1:%d", proxy)
	proxyUrl, err := url.Parse(full)
	if err != nil {
		fmt.Println("Invalid proxy URL:", err)
		return &http.Client{}
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyUrl),
	}
	return &http.Client{Transport: transport}
}
