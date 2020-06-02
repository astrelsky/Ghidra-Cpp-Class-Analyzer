package ghidra.app.plugin.prototype.typemgr.icon;

import java.awt.image.ColorModel;

public final class RedGreenSwappedColorModel extends AbstractSwappedColorModel {

	public RedGreenSwappedColorModel(ColorModel original) {
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

}