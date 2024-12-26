package com.example.anysale.likeList.dto;

import lombok.*;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LikeListDTO {

  private int id;                  // 찜 목록 ID
  private String itemCode;         //상품 코드, 찜한 상품의 고유 코드
  private String memberId;         //멤버아이디, 찜한 회원의 ID
  private String title;            // 상품명
  private String location;         // 주소
  private String category;         // 카테고리
  private long price;              // 금액

  // 모든 필드를 초기화하는 생성자
  public LikeListDTO(String itemCode, String memberId) {
    this.itemCode = itemCode; //상품 코드 설정
    this.memberId = memberId; //멤버 아이디 설정
  }
}