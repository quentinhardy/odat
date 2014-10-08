# -*- mode: python -*-

block_cipher = None


a = Analysis(['odat.py'],
             pathex=['/home/bobsecurity/odat'],
             hiddenimports=[],
             hookspath=['/usr/lib/python2.7/dist-packages/scapy/layers/'],
             runtime_hooks=None,
             cipher=block_cipher)
pyz = PYZ(a.pure,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='odat-libc2.19-x86_64',
          debug=False,
          strip=True,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=True,
               upx=True,
               name='odat-libc2.19-x86_64')
