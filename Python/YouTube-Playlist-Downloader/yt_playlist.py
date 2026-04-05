import yt_dlp

playlist_url = input('Enter playlist URL: ')

ydl_opts = {
    'outtmpl': '%(playlist_title)s/%(title)s.%(ext)s',
}

with yt_dlp.YoutubeDL(ydl_opts) as ydl:
    ydl.download([playlist_url])