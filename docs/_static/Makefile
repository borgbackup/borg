
all: logo.pdf logo.png

logo.pdf: logo.svg
	inkscape logo.svg --export-pdf=logo.pdf

logo.png: logo.svg
	inkscape logo.svg --export-png=logo.png --export-dpi=72,72

clean:
	rm -f logo.pdf logo.png
