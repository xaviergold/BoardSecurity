package com.board.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LikeDTO {
	private int seqno;
	private String userid;
	private String mylikecheck;
	private String mydislikecheck;
	private String likedate;
	private String dislikedate;

}
