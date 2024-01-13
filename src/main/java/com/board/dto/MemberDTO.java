package com.board.dto;

import java.time.LocalDate;
import java.util.Date;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberDTO {
	private String userid;
	private String username;
	private String password;
	private String job;
	private String gender;
	private String hobby;
	private String telno;
	private String email;
	private String zipcode;
	private String address;
	private String description;
	private LocalDate regdate;
	private LocalDate lastlogindate;
	private LocalDate lastlogoutdate;
	private LocalDate lastpwdate;
	private int pwcheck;
	private String role;
	private String org_filename;
	private String stored_filename;
	private long filesize;
	private String authkey;	
	
}
