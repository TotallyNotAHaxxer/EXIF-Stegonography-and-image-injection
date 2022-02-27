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

```
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
00000010  00 00 02 e5 00 00 02 79  08 06 00 00 00 09 9e 4e  |.......y.......N|
00000020  c6 00 00 80 00 49 44 41  54 78 da ec bd 07 58 54  |.....IDATx....XT|
00000030  59 b6 b7 7f a7 7b 42 cf  f4 cc b4 6d 8e 6d 77 db  |Y....{B....m.mw.|
00000040  39 99 30 e7 4c ce 59 51  01 15 03 8a a2 e4 9c 93  |9.0.L.YQ........|
00000050  64 c9 39 57 26 09 88 59  40 25 a8 08 82 44 c1 d4  |d.9W&..Y@%...D..|
00000060  e6 88 28 50 55 e7 fc be  7d 0e 38 b7 ef fc e7 bb  |..(PU...}.8.....|
00000070  77 fe f7 de 99 e9 99 6f  bf cf b3 9e aa 3a 75 ce  |w......o.....:u.|
00000080  29 0a a5 f6 7b 56 ad bd  f6 bf fd 1b 85 42 a1 50  |)...{V.......B.P|
00000090  28 14 0a 85 42 a1 50 28  14 ca 3f 02 00 bf 20 f1  |(...B.P(..?... .|
000000a0  ce 5f 88 5f bc 8d 9f ec  f7 e7 f1 76 df 77 ff 2c  |._._.......v.w.,|
000000b0  7e 41 7f b3 14 0a 85 42  a1 50 28 14 ca 5f 27 e4  |~A.....B.P(.._'.|
```

Hmmm what do you see? it should be easy to see. .PNG would be our first clue, so in order to veryify the image is a PNG image it is read in what is called the header of the file, the header of a file is the very top / start of the file. this is also why you can not just change a png extension to jpg, its simply becuase the image format type is embedded into the binary of the file. now when we look at the very first line which is looked at as the first 8 bytes mine is 

*89 50 4e 47 0d 0a 1a 0a*

This is how we identify the header of the file

Now the second, third and the fourth values are also in a sense the same, once conerted to ascii they literally read PNG, Now the header sequence in this file consists of two types of arbitrary tailing bytes which canist of both DOS and UNIX carriage return line feed (CRLF) ( Often 00000050  39 fb bc 9c 92 47 d4 4d  00 

refered to as the files magic bytes )

**chunk sequence**

If you look at the hex dump further along you can see some weird tags like IDAT, and IHDR which are tags that define the type and size of the image along with the header, ( also why they are set at the header of the dump ), 

```
00 00 00 0d 49 48 44 52  |.PNG........IHDR|
00000010  00 00 02 e5 00 00 02 79  08 06 00 00 00 09 9e 4e  |.......y.......N|
```

IHDR is another tag to look at, in order for tools to read and convert the binary data of the image to meta data they need to look for tags like the IHDR tags which define the images metadata, what we will mosly be looking out for as a location to inject will be known as the IEND chunk, the IEND chunk is the images or PNG's EOF ( End of file ), before i go on might i say along with this technique of image injection there are many many many MANY other techniques to inject images with payloads, in this section we will focus on a method of writing data to a certian byte offset ( The IEND offset ), The reason we are going to inject our data into the IEND chunk type is because images like PNG image formats define chunks and classifies them as critical or ancillary, the reason they are classified this way is to define what data is important in the image and whaty is not, the IEND chunk is an ideal injection point because it is not critical to have inside of the image, while it is used alot and needed needed for the image to run it is not as critical as much as the metadata of the image is.

to locate this offset lets scroll all the way down to the bottom of the hex dump 

```
00000050  39 fb bc 9c 92 47 d4 4d  00 00 00 00 49 45 4e 44  |9....G.M....IEND|
00000060  ae 42 60 82 e6 4d 9f ec  fb d3 c7 9f ae 6d 6e de  |.B`..M.......mn.|
00000070  39 eb c8 91 03 b9 bb 77  ef 96 6e dd ba 35 7c fb  |9......w..n..5|.|
00000080  f6 ed 21 df ee fd 36 00  1f a7 b3 4f 35 ba e3 a5  |..!...6....O5...|
00000090  4b 97 fc 8e 1e 3d 1a 74  e8 d0 a1 30 32 f6 ef df  |K....=.t...02...|
000000a0  1f ba 7b eb ee 60 fc 9e  87 83 bc 77 c7 8e 1d a1  |..{..`.....w....|
000000b0  7b f7 ee 0d 21 af 25 ef  f1 b5 c7 f5 b9 06 46 c8  |{...!.%.......F.|
000000c0  19 18 18 18 18 18 18 18  18 fe ab 49 bb af bd df  |...........I....|
000000d0  e3 70 03 42 6f 5c b9 a1  3b 77 ee 5c da 0f 67 ce  |.p.Bo\..;w.\..g.|
000000e0  14 9e 3e 7d 7a ec 77 df  7d 5f 71 fa f4 d9 d2 b3  |..>}z.w.}_q.....|
000000f0  67 cf e5 60 e2 6c be 79  f3 66 b8 8f 6d 60 87 ff  |g..`.l.y.f..m`..|
```

im sure by now you spotted the IEND chunk for us this chunk is located at offset `0x85258` if you can not find the offset on your own no need to worry, i have a decent tool for you, so in my github i have a tool called EXIF hunter, which is a tool to inject JPEG, JPG, PNG image formats and find metadata on the image, when you install this tool 

`git clone https://github.com/ArkAngeL43/EXIF-Hunter-V1.0.git ; cd EXIF-Hunter-V1.0 ; chmod +x ./install.sh ; ./install.sh`

then you can run the command as follows 

`go run main.go -i your_image.png --meta`

which once run you will get a large table and be asked `Would you like to locate just the IEND chunk? and injectable offset <y/n > ` once you say yes or y you will get 

```
 +---------------+-------------------------------+--------------------------------------+
|    Chunk Type |    Location Injectable OFFSET |    Injectable OFFSET HEX Translation |
+===============+===============================+======================================+
|          IEND |                        545368 |                              0x85258 |
+---------------+-------------------------------+--------------------------------------+
```

now that we have all the offset and enough knowlege to grab the offset we can now inject our data into the image.

> Injecting data 

Im going to start this section off by saying sorry XD, the last section was very very disorganized so to coninue into this one im going to explain some things i missed, the most important was EXIF-Hunter, if you dont know EXIF-Hunter is a image injection tool, payload encoder, meta data miner, geo location, and ZIP extraction utility for image formats of JPG/JPEG and PNG. This tool can aid in terms or lessons like this by helping you extract the meta data like chunks, chunk offsets, encoding payloads, and retrieving ZIP files embedded into images. Another thing i missed was 
