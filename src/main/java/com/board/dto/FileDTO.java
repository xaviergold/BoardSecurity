package com.board.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FileDTO {
	private int fileseqno;
	private int seqno;
	private String userid;
	private String org_filename;
	private String stored_filename;
	private long filesize;
	private String checkfile;

}
