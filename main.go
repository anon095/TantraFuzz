package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	// A popular and easy-to-use library for adding colors to terminal output.
	"github.com/logrusorgru/aurora"
)

// asciiArtFigures holds the different characters that can be displayed.
// New figures can be easily added to this map.
var asciiArtFigures = map[string]string{
	"cow": `
         \   ^__^
          \  (oo)\_______
             (__)\       )\/\
                 ||----w |
                 ||     ||
`,
	"tux": `
         \
          \
             .--.
            |o_o |
            |:_/ |
           //   \ \
          (|     | )
         /'\_   _/`\
         \___)=(___/
`,
	"dragon": `
         \                      /
          \                    /
           \    \   /    /
            \  _ \ / _  /
             \/ \/ \/ \/
             |/o_o\|
             |:_/ |
            _|\_v_/|_
           //|  |  |\\
          // |  |  | \\
         //  |  |  |  \\
        //   |  |  |   \\
       //    |  |  |    \\
      //     |  |  |     \\
     //      |  |  |      \\
    //       |  |  |       \\
   //        |  |  |        \\
  //         |  |  |         \\
 //          |  |  |          \\
(|           |  |  |           |)
 \           |  |  |           /
  \          |  |  |          /
   \         |  |  |         /
    \        |  |  |        /
     \       |  |  |       /
      \      |  |  |      /
       \     |  |  |     /
        \    |  |  |    /
         \   |  |  |   /
          \  |  |  |  /
           \ |  |  | /
            \|  |  |/
             |  |  |
             |  |  |
             |  |  |
             |  |  |
             |  |  |
             |  |  |
             |  |  |
             |__|__|
             |__|__|
             |__|__|
             |__|__|
             (____)
             (____)
`,
}

// rainbow applies a rainbow gradient effect to a string using ANSI escape codes.
func rainbow(text string) string {
	var builder strings.Builder
	// The "frequency" determines how quickly the color changes.
	// Smaller frequency -> slower color change.
	frequency := 0.1
	for i, char := range text {
		// Use sine waves to smoothly transition between RGB values
		red := uint8(math.Sin(frequency*float64(i)+0)*127 + 128)
		green := uint8(math.Sin(frequency*float64(i)+2*math.Pi/3)*127 + 128)
		blue := uint8(math.Sin(frequency*float64(i)+4*math.Pi/3)*127 + 128)

		// The aurora library can create a color from RGB values
		if char != '\n' { // Avoid coloring newline characters
			builder.WriteString(aurora.RGB(red, green, blue, string(char)).String())
		} else {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

// formatMessageInBubble wraps a given message inside an ASCII art speech bubble.
func formatMessageInBubble(message string, maxWidth int) string {
	var lines []string
	var longestLine int

	// Perform word wrapping
	words := strings.Fields(message)
	if len(words) == 0 {
		return "" // Return empty if there's no message
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) > maxWidth {
			lines = append(lines, currentLine)
			if len(currentLine) > longestLine {
				longestLine = len(currentLine)
			}
			currentLine = word
		} else {
			currentLine += " " + word
		}
	}
	lines = append(lines, currentLine)
	if len(currentLine) > longestLine {
		longestLine = len(currentLine)
	}

	var builder strings.Builder

	// Top border of the bubble
	builder.WriteString(" " + strings.Repeat("_", longestLine+2) + "\n")

	// Message content with side borders
	for i, line := range lines {
		padding := strings.Repeat(" ", longestLine-len(line))
		leftBorder, rightBorder := "|", "|"
		if len(lines) == 1 {
			leftBorder, rightBorder = "<", ">"
		} else if i == 0 {
			leftBorder, rightBorder = "/", "\\"
		} else if i == len(lines)-1 {
			leftBorder, rightBorder = "\\", "/"
		}
		builder.WriteString(fmt.Sprintf("%s %s%s %s\n", leftBorder, line, padding, rightBorder))
	}

	// Bottom border of the bubble
	builder.WriteString(" " + strings.Repeat("-", longestLine+2) + "\n")
	return builder.String()
}

func main() {
	// Define command-line flags for user input
	message := flag.String("m", "", "Message to be displayed")
	figure := flag.String("f", "cow", "ASCII figure to display (e.g., cow, tux, dragon)")
	listFigures := flag.Bool("l", false, "List available figures")
	width := flag.Int("w", 40, "Max width of the speech bubble")
	flag.Parse()

	// If the -l flag is used, list the figures and exit
	if *listFigures {
		fmt.Println("Available figures:")
		for name := range asciiArtFigures {
			fmt.Printf("- %s\n", name)
		}
		os.Exit(0)
	}

	// If no message is passed via the -m flag, try to read from standard input.
	// This allows for piping data from other programs (e.g., `fortune | ./my-cowsay`).
	if *message == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			reader := bufio.NewReader(os.Stdin)
			var sb strings.Builder
			for {
				r, _, err := reader.ReadRune()
				if err != nil && err == io.EOF {
					break
				}
				sb.WriteRune(r)
			}
			*message = strings.TrimSpace(sb.String())
		} else {
			// If no message is provided at all, show usage instructions and exit.
			fmt.Println("No message provided. Use -m \"Your message\" or pipe data to the program.")
			fmt.Println("Example: fortune | ./yourprogram -f dragon")
			os.Exit(1)
		}
	}

	// Get the selected ASCII art, defaulting to "cow" if the chosen figure is not found.
	art, ok := asciiArtFigures[*figure]
	if !ok {
		fmt.Printf("Warning: Figure '%s' not found, defaulting to 'cow'.\n", *figure)
		art = asciiArtFigures["cow"]
	}

	// Format the speech bubble, apply the rainbow effect, and print to the console.
	bubble := formatMessageInBubble(*message, *width)
	fmt.Print(rainbow(bubble))
	fmt.Print(rainbow(art))
}

