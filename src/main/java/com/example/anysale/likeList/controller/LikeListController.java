package com.example.anysale.likeList.controller;

import com.example.anysale.likeList.entity.LikeList;
import com.example.anysale.likeList.service.LikeListService;
import com.example.anysale.member.entity.Member;
import com.example.anysale.member.service.MemberService;
import com.example.anysale.product.dto.ProductDTO;
import com.example.anysale.product.entity.Product;
import com.example.anysale.product.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/likeList")
public class LikeListController {

  @Autowired
  private ProductService productService;

  @Autowired
  private LikeListService likeListService;

  @Autowired
  private MemberService memberService;

  // 상품 세부 정보 조회
  @GetMapping("/{id}")
  public String getProductDetails(@PathVariable String id, Model model) {
    ProductDTO product = productService.getProductById(id).orElse(null);

    if (product != null) {
      model.addAttribute("title", product.getTitle());  // title 값을 Model에 추가
    } else {
      model.addAttribute("error", "상품을 찾을 수 없습니다.");
    }

    return "like/likeList";  // 해당하는 HTML 페이지를 반환
  }

  // ?
  // 찜하기 버튼 클릭 처리
  @PostMapping
  public ResponseEntity<String> addToLikeList(Principal principal, @RequestParam("itemCode") String itemCode) {
    try {

      String memberId = principal.getName();

      Member member = Member.builder().id(memberId).build();

      Product product = Product.builder().itemCode(itemCode).build();

      LikeList likeList = LikeList.builder().member(member).product(product).build();

      likeListService.addLikeList(likeList);
      return ResponseEntity.ok("찜하기 성공");
    } catch (Exception e) {
      e.printStackTrace(); // 오류 로그 출력
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("서버 오류 발생");
    }
  }

  @GetMapping("/list")
  public String getLikeLists(Model model, Principal principal) {

    // SecurityContextHolder에서 사용자 정보 가져오기
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
    }

    // 사용자 ID 가져오기
    String userId = authentication.getName(); // 인증된 사용자 ID
    Member member = memberService.getMemberById(userId).orElse(null);

    model.addAttribute("member", member);

    if (principal == null) {
      return "redirect:/login"; // 로그인 페이지로 리다이렉트
    }

    String memberId = principal.getName();
    List<ProductDTO> likeLists = likeListService.getLikeList(memberId);
    model.addAttribute("likeList", likeLists);

    return "like/likeList";
//    return ResponseEntity.ok(likeLists);
  }

//  // 찜 목록에서 특정 상품 제거
  @DeleteMapping("/{likeListId}")
  public ResponseEntity<Void> removeLikeList(@PathVariable int likeListId) {
    LikeList removedLikeList = likeListService.removeLikeList(likeListId);
    if (removedLikeList != null) {
      return new ResponseEntity<>(HttpStatus.OK);
    } else {
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
  }
//
//  // 찜 목록에서 모든 상품 제거
//  @DeleteMapping("/all/{memberId}")
//  public ResponseEntity<Void> removeAllLikeLists(@PathVariable String memberId) {
//    likeListService.removeAllLikeList(memberId);
//    return new ResponseEntity<>(HttpStatus.OK);
//  }
}