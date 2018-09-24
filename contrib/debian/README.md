
Debian
====================
This directory contains files used to package imadad/imada-qt
for Debian-based Linux systems. If you compile imadad/imada-qt yourself, there are some useful files here.

## imada: URI support ##


imada-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install imada-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your imadaqt binary to `/usr/bin`
and the `../../share/pixmaps/imada128.png` to `/usr/share/pixmaps`

imada-qt.protocol (KDE)

