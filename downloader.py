import yt_dlp

url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"  # example

input = input("Enter URL: ")

ydl_opts = {
    'outtmpl': 'downloaded_video.%(ext)s'
}

with yt_dlp.YoutubeDL(ydl_opts) as ydl:
    ydl.download([input])
