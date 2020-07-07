package cppclassanalyzer.plugin.typemgr.icon;

import java.awt.image.ColorModel;

public final class BlueGreenSwappedColorModel extends AbstractSwappedColorModel {

	public BlueGreenSwappedColorModel(ColorModel original) {
		super(original);
	}

	@Override
	public int getGreen(int pixel) {
		return getOriginal().getBlue(pixel);
	}

	@Override
	public int getBlue(int pixel) {
		return getOriginal().getGreen(pixel);
	}

}
