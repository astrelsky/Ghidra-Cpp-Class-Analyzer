package cppclassanalyzer.plugin.typemgr.icon;

import java.awt.image.ColorModel;

public class PurpleSwappedColorModel extends AbstractSwappedColorModel {

	public PurpleSwappedColorModel(ColorModel original) {
		super(original);
	}

	@Override
	public int getRed(int pixel) {
		return getOriginal().getGreen(pixel);
	}

	@Override
	public int getGreen(int pixel) {
		return getOriginal().getRed(pixel);
	}

	@Override
	public int getBlue(int pixel) {
		return getOriginal().getGreen(pixel);
	}
}
