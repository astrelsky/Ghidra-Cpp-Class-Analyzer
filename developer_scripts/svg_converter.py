import argparse
from pathlib import Path
from PyQt5.QtCore import QSize # pylint: disable=no-name-in-module
from PyQt5.QtGui import QIcon, QImage # pylint: disable=no-name-in-module
from PyQt5.QtWidgets import QApplication # pylint: disable=no-name-in-module

parser = argparse.ArgumentParser()
parser.add_argument("input", help="input svg file", type=Path)
parser.add_argument("output", help="output png file", type=Path)
parser.add_argument("size", help="output image size (w,h)", nargs=2, type=int)

if __name__ == '__main__':
    args = parser.parse_args()
    assert args.input.exists(), "Input file does not exist"
    app = QApplication([])
    icon = QIcon(str(args.input))
    size = QSize(*args.size)
    pixmap = icon.pixmap(size)
    image = pixmap.toImage()
    image.save(str(args.output))
