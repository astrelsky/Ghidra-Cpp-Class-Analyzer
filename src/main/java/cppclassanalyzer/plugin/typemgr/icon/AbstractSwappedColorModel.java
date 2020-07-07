package cppclassanalyzer.plugin.typemgr.icon;

import java.awt.image.ColorModel;
import java.awt.image.Raster;

abstract class AbstractSwappedColorModel extends ColorModel {

	private final ColorModel original;

	AbstractSwappedColorModel(ColorModel original) {
		super(original.getPixelSize());
		this.original = original;
	}

	final ColorModel getOriginal() {
		return original;
	}

	@Override
	public final boolean isCompatibleRaster(Raster raster) {
		return original.isCompatibleRaster(raster);
	}

	@Override
	public int getRed(int pixel) {
		return original.getRed(pixel);
	}

	@Override
	public int getGreen(int pixel) {
		return original.getGreen(pixel);
	}

	@Override
	public int getBlue(int pixel) {
		return original.getBlue(pixel);
	}

	@Override
	public final int getAlpha(int pixel) {
		return original.getAlpha(pixel);
	}
}
