package com.board.mapper;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;

import com.board.dto.BoardDTO;
import com.board.dto.FileDTO;
import com.board.dto.LikeDTO;
import com.board.dto.ReplyDTO;

@Mapper
public interface BoardMapper {
	//게시물 목록 보기
	public List<BoardDTO> list(Map<String, Object> data) throws Exception;
	
	//게시물 전체 갯수 계산
	public int getTotalCount(String keyword) throws Exception;
	
	//게시물 상세 내용 보기
	public BoardDTO view(int seqno) throws Exception;
	
	//게시물 내용 이전 보기
	public int pre_seqno(Map<String, Object> data) throws Exception;
	
	//게시물 내용 다음 보기
	public int next_seqno(Map<String, Object> data) throws Exception;
	
	//게시물 조회수 증가
	public void hitno(int seqno) throws Exception;
	
	//게시물 등록 하기
	public void write(BoardDTO board) throws Exception;
	
	//게시물 번호 구하기(시퀀스의 nextval을 사용)
	public int getSeqnoWithNextval() throws Exception;
	
	//첨부파일 등록하기
	public void fileInfoRegistry(Map<String,Object> data) throws Exception;
	
	//첨부파일 목록 보기
	public List<FileDTO> fileInfoView(int seqno) throws Exception;
	
	//첨부 파일 삭제를 위한 checkfile 정보 변경
	public void fileInfoUpdate(int seqno) throws Exception;
	
	//다운로드를 위한 파일 정보 가져 오기
	public FileDTO fileInfo(int fileseqno) throws Exception;

	//게시물 수정
	public void modify(BoardDTO board) throws Exception;	
	
	//게시물 좋아요/싫어요 수정
	public void boardLikeUpdate(BoardDTO board) throws Exception;
	
	//게시물 삭제하기
	public void delete(int seqno) throws Exception;	
	
	//게시물 수정 시 파일 정보 수정(checkfile을 X로 변경)
	public void deleteFileList(int fileseqno) throws Exception;
	
	//좋아요/싫어요 등록여부 확인
	public LikeDTO likeCheckView(LikeDTO likeData) throws Exception;
	
	//좋아요/싫어요 신규 등록
	public void likeCheckRegistry(LikeDTO likeData) throws Exception;
	
	//좋아요/싫어요 수정
	public void likeCheckUpdate(LikeDTO likeData) throws Exception;
	
	//댓글 목록 보기
	public List<ReplyDTO> replyView(ReplyDTO reply) throws Exception;
	
	//댓글 등록 
	public void replyRegistry(ReplyDTO reply) throws Exception;
	
	//댓글 수정
	public void replyUpdate(ReplyDTO reply) throws Exception;
	
	//댓글 삭제 
	public void replyDelete(ReplyDTO reply) throws Exception;	

}
