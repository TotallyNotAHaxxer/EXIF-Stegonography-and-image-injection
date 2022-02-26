# EXIF-Stegonography-and-image-injection

```

   ___            __ _                                         _           
  / _ \___       / _\ |_ ___ _ __   ___   __ _ _ __ __ _ _ __ | |__  _   _ 
 / /_\/ _ \ _____\ \| __/ _ \ '_ \ / _ \ / _` | '__/ _` | '_ \| '_ \| | | |
/ /_\\ (_) |_____|\ \ ||  __/ | | | (_) | (_| | | | (_| | |_) | | | | |_| |
\____/\___/      \__/\__\___|_| |_|\___/ \__, |_|  \__,_| .__/|_| |_|\__, |
                                         |___/          |_|          |___/
```

Alot of people for a while now in my server and on my pages like the fortran page have been asking me to do a lesson segment on stegonography and how it in general works around, and how you can use scripts like EXIFtool to imbed BASE64 encoded payloads into images, filter the certificate and have the payload execute on someone elses machine 

What will this page / lesson teach?

> How stenography works
 
> Stenography with JPG/JPEG/PNG image formats

> How to hide files / ZIP files inside of JPEG / JPG formats with go 

> How to base64 encode a paylaod 

> How to hide a base64 encoded payload into a JPG file 

> How to filter out and execute the payload in the image from a post forum

> How to inject data into images with EXIF-Hunter

> How to find the binary offsets and chunk types using EXIF hunter 

> How to find chunk offsets in PNG images by yourself

> How to Geo locate and understand geo location tags in JPG/JPEG image formats 

> How to extract metadata out of image files using EXIFTOOL

> How to EXTRACT ZIP files using EXIF-Hunter 

> How to build your own GO script to extract ZIP files in JPG/JPEG image formats

Wow alot right? thats alright it should not take that long, by the end of this reading you should be able to understand how stenography works, and how to build your own scripts in go to automate the skills you learned here, just like the fortran95 lesson on math see this link here -> https://github.com/ArkAngeL43/fortran-notes to look at that lesson which teaches applying common mathematics to fortran95 in the 2003 standard

# Starting out with the basics 

> What is stenography? 

Stenography is a process hackers or in some cases organizations use to hide data inside of images, this can be something as small as an encrypted or base64 encoded message to someone, or something as big as a data leak and ZIP file which can execute remote code or holds very very important data. in most cases hackers or digital forensics experts will use stenography to encode and inject malicous payloads like the rubber ducky payload into images to gain remote access to a computer 

> How can this aid hackers in attacks and how is this better than normal malware?

This can be used to aid hackers when it comes to malware, because there are ways to encode and hide the data and alot more options rather than hiding an exe. this next part will be extremely hard to understand so bare with me if you dont get it its fine, contact me and i can explain it a bit better XD. 

Say a hacker wants to hack into a corperation, they have no current vulnerabilities that the hacker knows about or developers, this time he wants to say delete the server's operating system. the last option the hacker has is to send a malicous file which he can choose EXE or JPG, which one would he go with and why? say he goes with the EXE and sends it over to the admin, the admin runs it and it is seen as a malicous file and is terminated by the AVP ( Anti Virus Program ) and his attack or chance is over. Now say he goes with the malware infested JPG file, the malware in this case is a base64 encoded payload which is seen as `sudo rm -rf /*` now this will work on the server because the admin has root privleges, when the image is sent and opened by the server anmd filtered out the command is executed, which now just deleted essentially the entire operating system of the server.

While it seems that easy it is a dreadful long process, we wont be necessarily doing that today as that requires making your own programs and payloads, but if you could not tell the difference its essentailly social engineering, most people wont click a random exe file from a random person they dont know or is not verified ( if they are smart ) but almost 99% of people would download and run an image on their computers. Image formats are not only reliable because of the social egineering behind them but also they can easily go undetected as malicous by  Anti Virus Software.

> The basics of PNG images 

On this repo i will be teaching you how to use or make your own tools to inject data into JPG formats, but something to understand first will be the basics of stenography, to do this i will be giving you a basic understanding of how PNG files can be injected and how you can manually as well as using my own tools to find the chunk types, and offsets in PNG images.

# Understanding, injecting, and finding chunks in png image formats 

> Locating offsets, and chunks

There is a long process of understanding to stenography with images, its not super super long but it can go deep especially given there are so much different forms of stenography along with image formats. To start this topic off we will be talking about the metadata / recon part of stenography which is quite fairly easy, all you need is a PNG image, and a hex dumping utility. Hex dumping is amazing for this kind of stuff because it allows you to find certian data and filter it out, as well as finding chunk type offsets.

**Building your own command line interface hex dumping utility**

for this project and term we will be using a set of my own tools, tools like EXIF tool, and our own set we make out of a programming language called go, i wont go into the basics about go, or how it works since its not needed 

**script**

```go
package main

import (  
    "bufio"
    "encoding/hex"
    "fmt"
    "log"
    "os"
    "io"
)

func main() {
    filename := os.Args[1]  
    f, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    reader := bufio.NewReader(f)
    buf := make([]byte, 256)
    for {
        _, err := reader.Read(buf)
        if err != nil {
            if err != io.EOF {
                fmt.Println(err)
            }
            break
        }
        fmt.Printf("%s", hex.Dump(buf))
    }
}
```

this script is easy to work with, simple save the file as main.go, and run it as go run main.go yourimage.png

for this example i will be using the image below 

**image**

![im](git/battlecat.png)


we will run the script as follows *go run main.go battlecat.png* when we run the tool we will get the output of a large hex and example is seen down below at the very top of the hex dump.
