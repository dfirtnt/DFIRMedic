package ui

import "strings"

// 5x5 glyphs, '#' = filled. Only the letters the beacon needs, plus space.
var font = map[rune][5]string{
	'A': {" ### ", "#   #", "#####", "#   #", "#   #"},
	'C': {" ####", "#    ", "#    ", "#    ", " ####"},
	'D': {"#### ", "#   #", "#   #", "#   #", "#### "},
	'E': {"#####", "#    ", "#### ", "#    ", "#####"},
	'G': {" ####", "#    ", "#  ##", "#   #", " ####"},
	'I': {"#####", "  #  ", "  #  ", "  #  ", "#####"},
	'N': {"#   #", "##  #", "# # #", "#  ##", "#   #"},
	'O': {" ### ", "#   #", "#   #", "#   #", " ### "},
	'R': {"#### ", "#   #", "#### ", "#  # ", "#   #"},
	'S': {" ####", "#    ", " ### ", "    #", "#### "},
	'T': {"#####", "  #  ", "  #  ", "  #  ", "  #  "},
	'Y': {"#   #", " # # ", "  #  ", "  #  ", "  #  "},
	' ': {"     ", "     ", "     ", "     ", "     "},
}

// BigText renders s (uppercased) as five rows of block glyphs separated by one column.
func BigText(s string) []string {
	rows := make([]string, 5)
	for i, r := range strings.ToUpper(s) {
		g, ok := font[r]
		if !ok {
			g = font[' ']
		}
		for row := 0; row < 5; row++ {
			if i > 0 {
				rows[row] += " "
			}
			rows[row] += strings.ReplaceAll(g[row], "#", "█")
		}
	}
	return rows
}
