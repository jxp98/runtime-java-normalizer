package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"runtime-java-normalizer/internal/api"
	"runtime-java-normalizer/internal/normalizer"
)

func main() {
	inputPath := flag.String("input", "", "归一化请求 JSON 文件路径；为空时从标准输入读取")
	flag.Parse()

	var (
		content []byte
		err     error
	)

	if *inputPath != "" {
		content, err = os.ReadFile(*inputPath)
	} else {
		content, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var request api.NormalizeRequest
	if err = json.Unmarshal(content, &request); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	response := normalizer.New().Normalize(request)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(response); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
