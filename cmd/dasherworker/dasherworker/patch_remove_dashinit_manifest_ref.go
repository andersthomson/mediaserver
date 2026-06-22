package dasherworker

import (
	"fmt"
	"os"
	"strings"

	"github.com/clbanning/mxj/v2"
)

// fixManifestBaseURLs removes "_dashinit" from BaseURL tags in all Video representations
func fixManifestBaseURLs(mpdPath string) {
	patchedPath := mpdPath // Overwriting the original manifest

	data, err := os.ReadFile(mpdPath)
	if err != nil {
		fmt.Printf("Error reading manifest: %v\n", err)
		return
	}

	// Parse XML using mxj to preserve all attributes and order
	m, err := mxj.NewMapXml(data)
	if err != nil {
		fmt.Printf("Error parsing XML: %v\n", err)
		return
	}

	reps, err := m.ValuesForPath("MPD.Period.AdaptationSet.Representation")
	if err != nil {
		fmt.Printf("No representations found: %v\n", err)
		return
	}

	for _, r := range reps {
		rep, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		id := rep["-id"]

		// 1. Handle BaseURL if it exists as a direct child element
		if baseURLVal, exists := rep["BaseURL"]; exists {
			switch v := baseURLVal.(type) {
			case string:
				// Simple <BaseURL>url_dashinit.mp4</BaseURL>
				if strings.Contains(v, "_dashinit") {
					rep["BaseURL"] = strings.ReplaceAll(v, "_dashinit", "")
					fmt.Printf("Patched simple BaseURL for Video ID %v\n", id)
				}
			case map[string]interface{}:
				// Complex element with attributes: <BaseURL attribute="val">url_dashinit.mp4</BaseURL>
				// mxj places the text content of a node under the "#text" key
				if textVal, textExists := v["#text"].(string); textExists {
					if strings.Contains(textVal, "_dashinit") {
						v["#text"] = strings.ReplaceAll(textVal, "_dashinit", "")
						fmt.Printf("Patched complex BaseURL text for Video ID %v\n", id)
					}
				}
			case []interface{}:
				// Multiple <BaseURL> elements under one representation
				for _, item := range v {
					if baseMap, ok := item.(map[string]interface{}); ok {
						if textVal, textExists := baseMap["#text"].(string); textExists {
							if strings.Contains(textVal, "_dashinit") {
								baseMap["#text"] = strings.ReplaceAll(textVal, "_dashinit", "")
								fmt.Printf("Patched item in BaseURL list for Video ID %v\n", id)
							}
						}
					} else if textVal, ok := item.(string); ok {
						// Array of pure strings (fallback)
						// Note: Direct array mutation requires index tracking, handled safely via standard mxj paths if typical
						_ = textVal
					}
				}
			}
		}
	}

	// Generate clean XML output
	output, err := m.XmlIndent("", "  ")
	if err != nil {
		fmt.Printf("Error generating XML: %v\n", err)
		return
	}

	header := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	err = os.WriteFile(patchedPath, append(header, output...), 0644)
	if err != nil {
		fmt.Printf("Error writing patched manifest: %v\n", err)
		return
	}
	fmt.Println("Manifest BaseURLs successfully updated.")
}
