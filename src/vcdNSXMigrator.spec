# -*- mode: python ; coding: utf-8 -*-

# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Spec file which is used for packaging VMware Cloud Director NSX Migrator Tool.
"""

block_cipher = None


a = Analysis(['vcdNSXMigrator.py'],
             pathex=['/home/vagrant/vcd-migration/src'],
             binaries=[],
             datas=[('./*.yml', '.'), ('./commonUtils/*.yaml', './src/commonUtils'), ('./core/nsxt/template*', './src/core/nsxt'), ('./core/vcd/template*', './src/core/vcd')],
             hiddenimports=['pkg_resources.py2_warn'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='vcdNSXMigrator',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
