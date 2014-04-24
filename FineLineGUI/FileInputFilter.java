/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package FineLineGUI;

/**
 *
 * @author Derek
 */
import java.io.File;
import javax.swing.filechooser.FileFilter;

public final class FileInputFilter extends FileFilter {
	private String file_extension;
	private String description;

	public FileInputFilter(String file_extension, String descr) {
		this.file_extension = file_extension;
		this.description = descr;
	} // FileInputFilter

	public boolean accept(File file) {
		if(file.isDirectory()) return true;
		if (file_extension != null)
		    return file.getName().endsWith(file_extension);
		else
		    return true;
	} // accept

	public String getDescription() {
		return description;
	} // getDescription
} // class FileInputFilter
