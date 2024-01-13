package com.board.service;

import java.util.List;

import com.board.dto.AddressDTO;
import com.board.dto.MemberDTO;

public interface MemberService {

	//회원 가입
	public void memberInfoRegistry(MemberDTO member);
	
	//회원 정보 가져 오기
	public MemberDTO memberInfo(String userid);
	
	//아이디 중복 확인
	public int idCheck(String userid);
	
	//패스워드 수정
	public void memberPasswordModify(MemberDTO member);
	
	//마지막 로그인 날짜 등록 하기
	public void lastlogindateUpdate(MemberDTO member);
	
	//마지막 로그아웃 날짜 등록 하기
	public void lastlogoutdateUpdate(MemberDTO member);
	
	//아이디 찾기
	public String searchID(MemberDTO member);
	
	//임시 패스워드 생성
	public String tempPasswordMaker();
	
	//authkey 업데이트
	public void authkeyUpdate(MemberDTO member);
	
	//authkey 존재 여부 확인
	public MemberDTO memberInfoByAuthkey(MemberDTO member);
	
	//주소 검색
	public List<AddressDTO> addrSearch(int startPoint, int endPoint, String addrSearch);
	
	//주소 행 최대값 계산
	public int addrTotalCount(String addrSearch);
	
}
