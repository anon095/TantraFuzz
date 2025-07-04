package main

import "github.com/fatih/color"

func printBanner() {
	banner := `
████████╗ █████╗ ███╗   ██╗████████╗██████╗  █████╗ ██╗   ██╗██╗   ██╗
╚══██╔══╝██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗ ██╔╝╚██╗ ██╔╝
   ██║   ███████║██╔██╗ ██║   ██║   ██████╔╝███████║ ╚████╔╝  ╚████╔╝ 
   ██║   ██╔══██║██║╚██╗██║   ██║   ██╔══██╗██╔══██║  ╚██╔╝    ╚██╔╝  
   ██║   ██║  ██║██║ ╚████║   ██║   ██║  ██║██║  ██║   ██║      ██║   
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   
               ██████╗ ███████╗ ██████╗  ██████╗ ███╗   ██╗
               ██╔══██╗██╔════╝██╔═══██╗██╔═══██╗████╗  ██║
               ██████╔╝█████╗  ██║   ██║██║   ██║██╔██╗ ██║
               ██╔══██╗██╔══╝  ██║   ██║██║   ██║██║╚██╗██║
               ██║  ██║███████╗╚██████╔╝╚██████╔╝██║ ╚████║
               ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
     [ Real-Time AI-Assisted Attack Surface Management ]
`
	darkRed := color.New(color.FgRed)
	darkRed.Println(banner)
}
