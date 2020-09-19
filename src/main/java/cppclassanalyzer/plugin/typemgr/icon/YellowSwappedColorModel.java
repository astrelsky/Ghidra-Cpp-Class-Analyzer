package cppclassanalyzer.plugin.typemgr.icon;

import java.awt.image.ColorModel;

public final class YellowSwappedColorModel extends AbstractSwappedColorModel {

	public YellowSwappedColorModel(ColorModel original) {
		super(original);
	}

	@Override
	public int getRed(int pixel) {
		return getOriginal().getGreen(pixel);
	}

	@Override
	public int getBlue(int pixel) {
		return getOriginal().getBlue(pixel);
	}
	
}
