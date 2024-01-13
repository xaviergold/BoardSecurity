package com.board.dto;

import java.time.LocalDate;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ReplyDTO {
	private int replyseqno;
	private int seqno;
	private String userid;
	private String replywriter;
	private String replycontent;
	private LocalDate replyregdate;

}
