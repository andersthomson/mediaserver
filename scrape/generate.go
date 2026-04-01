package scrape

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/andersthomson/mediaserver/datasource"
)

func readGenerateFromFile(path string) (map[string]string, error) {
	fileHandle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fileHandle.Close()
	scanner := bufio.NewReader(fileHandle)
	res := make(map[string]string, 8)
	var methods []string
	for {
		textLine, err := scanner.ReadString('\n')
		if err == io.EOF {
			if len(textLine) != 0 {
				fmt.Print(textLine) // Print last line if not empty
			}
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading from file: %w", err)
		}
		//fmt.Print(textLine)
		splits := strings.SplitAfterN(textLine, "=", 2)
		switch len(splits) {
		case 2:
			key, _ := strings.CutSuffix(splits[0], "=")
			res[key] = splits[1][1 : len(splits[1])-2]
		case 1:
			if len(splits[0]) > 1 && strings.HasPrefix(splits[0], "generate_") {
				s2 := strings.Split(splits[0], "_")
				if len(s2) != 3 {
					panic(fmt.Sprintf("Trash on %s s2=%s\n", textLine, s2))
				}
				methods = append(methods, s2[1])
			}
		default:
			panic(34)
		}
	}
	res["methods"] = strings.Join(methods, ",")
	return res, nil
}

func DataSourceFromGenerate(logger *slog.Logger, caches []string, dir string, fname string) datasource.DataSource {
	g, err := readGenerateFromFile(dir + "/" + fname)
	if err != nil {
		return nil
	}
	if _, ok := g["TMDBMOVIE"]; ok {
		//spew.Dump(g)
		if d, ok := TMDBMovieFromGenerate(logger, caches, g, dir); ok {
			return d
		}
	}
	return nil
}
