package com.board;

import java.io.IOException;
import java.time.LocalDate;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.board.dto.MemberDTO;
import com.board.service.MemberService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler{
	
	private final MemberService service;
	
	//로그인 성공 시 해야할 명령문
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		//authentication.getName() --> 로그인 시 입력된 userid 값을 가져옴.
		MemberDTO member = service.memberInfo(authentication.getName());
		
		//마지막 로그인 날짜 등록
		member.setLastlogindate(LocalDate.now());
		service.lastlogindateUpdate(member);	
		
		//패스워드 확인 후 마지막 패스워드 변경일이 30일이 경과 되었을 경우 ...
		
		
		//세션 생성
		HttpSession session = request.getSession();
		session.setMaxInactiveInterval(3600*24*7);//세션 유지 기간 설정
		session.setAttribute("userid", service.memberInfo(member.getUserid()).getUserid());
		session.setAttribute("username", service.memberInfo(member.getUserid()).getUsername());
		session.setAttribute("role", service.memberInfo(member.getUserid()).getRole());
		
		setDefaultTargetUrl("/board/list?page=1");
		super.onAuthenticationSuccess(request, response, authentication);
		
	}

}
