package com.board.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.xml.crypto.dsig.XMLObject;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.board.dto.AddressDTO;
import com.board.dto.MemberDTO;
import com.board.mapper.MemberMapper;

@Service
public class MemberServiceImpl implements MemberService {

	@Autowired
	private MemberMapper mapper; 
	
	//회원 가입
	@Override
	public void memberInfoRegistry(MemberDTO member) {
		mapper.memberInfoRegistry(member);		
	}
	
	//회원 정보 가져 오기
	@Override
	public MemberDTO memberInfo(String userid) {
		return mapper.memberInfo(userid);
	}
	
	//아이디 중복 확인
	public int idCheck(String userid) {
		return mapper.idCheck(userid);
	};
	
	//패스워드 수정
	public void memberPasswordModify(MemberDTO member) {
		mapper.memberPasswordModify(member);
	}
	
	//마지막 로그인 날짜 등록 하기
	@Override
	public void lastlogindateUpdate(MemberDTO member) {
		mapper.lastlogindateUpdate(member);
	}
	
	//마지막 로그아웃 날짜 등록 하기
	@Override
	public void lastlogoutdateUpdate(MemberDTO member) {
		mapper.lastlogoutdateUpdate(member);
	}
	
	//아이디 찾기
	public String searchID(MemberDTO member) {
		return mapper.searchID(member);
	}
	
	//임시 패스워드 생성
	@Override
	public String tempPasswordMaker() {
		//숫자 + 영문대소문자 7자리 임시패스워드 생성
		StringBuffer tempPW = new StringBuffer();
		Random rnd = new Random();
		for (int i = 0; i < 7; i++) {
		    int rIndex = rnd.nextInt(3);
		    switch (rIndex) {
		    case 0:
		        // a-z : 아스키코드 97~122
		    	tempPW.append((char) ((int) (rnd.nextInt(26)) + 97));
		        break;
		    case 1:
		        // A-Z : 아스키코드 65~122
		    	tempPW.append((char) ((int) (rnd.nextInt(26)) + 65));
		        break;
		    case 2:
		        // 0-9
		    	tempPW.append((rnd.nextInt(10)));
		        break;
		    }
		}		
		return tempPW.toString();	
	}
	
	//authkey 업데이트
	@Override
	public void authkeyUpdate(MemberDTO member) {
		mapper.authkeyUpdate(member);
	}
	
	//authkey 존재 여부 확인
	@Override
	public MemberDTO memberInfoByAuthkey(MemberDTO member) {
		return mapper.memberInfoByAuthkey(member);
	}
	
	//주소 검색
	@Override
	public List<AddressDTO> addrSearch(int startPoint, int endPoint, String addrSearch) {
		Map<String,Object> data = new HashMap<>();
		data.put("startPoint", startPoint);
		data.put("endPoint", endPoint);
		data.put("addrSearch", addrSearch);
		return mapper.addrSearch(data);
	}

	//주소 행 최대 갯수 계산
	@Override
	public int addrTotalCount(String addrSearch) {
		return mapper.addrTotalCount(addrSearch);
	}

}
