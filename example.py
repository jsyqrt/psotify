# coding: utf-8
# spotify usage example

import sys

from psotify import *

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: python example.py username password (spotify premium account needed!)')
        sys.exit()
    
    username = sys.argv[1]
    password = sys.argv[2]
    sai = Spotify(username, password) # username, password of spotify premium account.

    album_ids = ['5MfAxS5zz8MlfROjGQVXhy', '02H4kc9YLgorpUIREOwa0q']
    artist_ids = ['1vPoTjMgGQuiCzsgvpASWW', '3yfDRplDZh03Y0fEeCd6B0']
    callback = lambda x, y: print(y, x[:30])
    
    for id in album_ids:
        sai.get_album_by_id(id, callback, metadata=id)
    for id in artist_ids:
        sai.get_artist_by_id(id, callback, metadata=id) 
