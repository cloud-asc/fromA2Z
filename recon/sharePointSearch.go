package recon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

func SearchSharePoint(access_token string, query string, limit int, socks int) {
	url := "https://graph.microsoft.com/v1.0/search/query"
	client := &http.Client{}
	from := 0
	size := 25
	reader := bufio.NewReader(os.Stdin)

	type FileResult struct {
		Index             int
		Name              string
		WebUrl            string
		Modified          string
		DriveId           string
		ItemId            string
		CachedDownloadUrl string
	}

	var files []FileResult
	total := 0

	for {
		if limit > 0 && len(files)+size > limit {
			size = limit - len(files)
		}

		payload := fmt.Sprintf(`{
			"requests": [{
				"entityTypes": ["driveItem"],
				"query": {
					"queryString": "%s"
				},
				"from": %d,
				"size": %d
			}]
		}`, query, from, size)

		req, err := http.NewRequest("POST", url, strings.NewReader(payload))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+access_token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request:", err)
			return
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 {
			ForbiddenSuggestion()
			return
		}

		var result struct {
			Value []struct {
				HitsContainers []struct {
					Hits []struct {
						Resource struct {
							Name                 string `json:"name"`
							WebUrl               string `json:"webUrl"`
							LastModifiedDateTime string `json:"lastModifiedDateTime"`
							Id                   string `json:"id"`
							ParentReference      struct {
								DriveId string `json:"driveId"`
							} `json:"parentReference"`
						} `json:"resource"`
					} `json:"hits"`
					Total                int  `json:"total"`
					MoreResultsAvailable bool `json:"moreResultsAvailable"`
				} `json:"hitsContainers"`
			} `json:"value"`
		}
		if len(body) == 0 {
			fmt.Println("Empty response App ID use does not have access to SharePoint")
			return
		}
		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}

		moreResults := false
		for _, val := range result.Value {
			for _, container := range val.HitsContainers {
				total = container.Total
				for _, hit := range container.Hits {
					files = append(files, FileResult{
						Index:    len(files) + 1,
						Name:     hit.Resource.Name,
						WebUrl:   hit.Resource.WebUrl,
						Modified: hit.Resource.LastModifiedDateTime,
						DriveId:  hit.Resource.ParentReference.DriveId,
						ItemId:   hit.Resource.Id,
					})
				}
				moreResults = container.MoreResultsAvailable
			}
		}

		if !moreResults || (limit > 0 && len(files) >= limit) {
			break
		}
		from += size
	}

	if len(files) == 0 {
		fmt.Println("No results found.")
		return
	}

	fmt.Printf("\nFound %d/%d results:\n\n", len(files), total)
	for i, f := range files {
		fmt.Printf("[%d] %s\n    URL: %s\n    Modified: %s\n", f.Index, f.Name, f.WebUrl, f.Modified)
		dlUrl := getDownloadUrl(f.DriveId, f.ItemId, access_token, socks)
		files[i].CachedDownloadUrl = dlUrl
		if isBinary(f.Name) {
			fmt.Println("    [binary file - preview skipped]")
		} else {
			previewFile(dlUrl, f.Name, access_token, 5, socks)
		}
		fmt.Println()
	}

	fmt.Println("Download options:")
	fmt.Println("  all       - download all files")
	fmt.Println("  1,2,3     - download specific files by index")
	fmt.Println("  1-5       - download a range")
	fmt.Println("  n         - skip")
	fmt.Print("\nSelection: ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "n" || input == "" {
		return
	}

	var toDownload []FileResult

	if input == "all" {
		toDownload = files
	} else if strings.Contains(input, "-") {
		var start, end int
		fmt.Sscanf(input, "%d-%d", &start, &end)
		for _, f := range files {
			if f.Index >= start && f.Index <= end {
				toDownload = append(toDownload, f)
			}
		}
	} else {
		parts := strings.Split(input, ",")
		indexMap := make(map[int]bool)
		for _, p := range parts {
			var idx int
			fmt.Sscanf(strings.TrimSpace(p), "%d", &idx)
			indexMap[idx] = true
		}
		for _, f := range files {
			if indexMap[f.Index] {
				toDownload = append(toDownload, f)
			}
		}
	}

	fmt.Printf("\nDownloading %d file(s)...\n", len(toDownload))
	for _, f := range toDownload {
		downloadFile(f.CachedDownloadUrl, f.Name, access_token, socks)
	}
}

func getDownloadUrl(driveId string, itemId string, access_token string, socks int) string {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/drives/%s/items/%s", driveId, itemId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := newHttpClient(socks)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Println("Error reading response:", err)
		return ""
	}

	var result struct {
		DownloadUrl string `json:"@microsoft.graph.downloadUrl"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("Error parsing response:", err)
		return ""
	}

	return result.DownloadUrl
}

func previewFile(downloadUrl string, filename string, access_token string, lines int, socks int) {
	if downloadUrl == "" {
		fmt.Println("    [no preview available]")
		return
	}

	req, err := http.NewRequest("GET", downloadUrl, nil)
	if err != nil {
		fmt.Println("    [preview error]")
		return
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := newHttpClient(socks)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("    [preview error]")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("    [preview failed: status %d]\n", resp.StatusCode)
		return
	}

	//fmt.Printf("    --- Preview: %s (first %d lines) ---\n", filename, lines)
	fmt.Println("================================================")
	scanner := bufio.NewScanner(resp.Body)
	count := 0
	for scanner.Scan() && count < lines {
		fmt.Printf("    %s\n", scanner.Text())
		count++
	}
	//fmt.Println("    --- End Preview ---")
	fmt.Println("================================================")

}

func downloadFile(downloadUrl string, filename string, access_token string, socks int) {
	if downloadUrl == "" {
		fmt.Println("No download URL available for this file")
		return
	}

	err := os.MkdirAll("sharepointLoot", 0755)
	if err != nil {
		fmt.Println("Error creating folder:", err)
		return
	}

	req, err := http.NewRequest("GET", downloadUrl, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := newHttpClient(socks)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Failed to download %s: status %d\n", filename, resp.StatusCode)
		return
	}

	filepath := fmt.Sprintf("sharepointLoot/%s", filename)

	if _, err := os.Stat(filepath); err == nil {
		ext := path.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		filepath = fmt.Sprintf("sharepointLoot/%s_%d%s", base, time.Now().Unix(), ext)
	}

	out, err := os.Create(filepath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}

	fmt.Printf("Downloaded: %s (%d bytes)\n", filepath, written)
}

func isBinary(filename string) bool {
	binaryExtensions := map[string]bool{
		// executables
		".exe": true, ".dll": true, ".bin": true, ".so": true,
		".dylib": true, ".sys": true, ".drv": true,
		// archives
		".zip": true, ".tar": true, ".gz": true, ".rar": true,
		".7z": true, ".bz2": true, ".xz": true, ".cab": true,
		".iso": true, ".dmg": true, ".pkg": true, ".deb": true,
		".rpm": true,
		// documents
		".pdf": true, ".doc": true, ".docx": true, ".xls": true,
		".xlsx": true, ".ppt": true, ".pptx": true, ".odt": true,
		".ods": true, ".odp": true, ".pages": true, ".numbers": true,
		// email
		".msg": true, ".eml": true, ".pst": true, ".ost": true,
		".mbox": true,
		// images
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".bmp": true, ".ico": true, ".svg": true, ".tiff": true,
		".webp": true, ".heic": true,
		// video
		".mp4": true, ".mov": true, ".avi": true, ".mkv": true,
		".wmv": true, ".flv": true, ".webm": true, ".m4v": true,
		// audio
		".mp3": true, ".wav": true, ".flac": true, ".aac": true,
		".ogg": true, ".wma": true, ".m4a": true,
		// database
		".db": true, ".sqlite": true, ".mdb": true, ".accdb": true,
		".bak": true,
		// compiled
		".class": true, ".pyc": true, ".pyo": true, ".o": true,
		".a": true, ".lib": true,
		// fonts
		".ttf": true, ".otf": true, ".woff": true, ".woff2": true,
		".eot": true,
		// misc binary
		".dat": true, ".raw": true, ".dump": true, ".img": true,
		".vhd": true, ".vmdk": true, ".ova": true, ".ovf": true,
	}
	ext := strings.ToLower(path.Ext(filename))
	return binaryExtensions[ext]
}
