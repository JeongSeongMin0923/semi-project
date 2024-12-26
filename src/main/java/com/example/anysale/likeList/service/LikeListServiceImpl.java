package com.example.anysale.likeList.service;

import com.example.anysale.likeList.entity.LikeList;
import com.example.anysale.likeList.repository.LikeListRepository;
import com.example.anysale.member.repository.MemberRepository;
import com.example.anysale.member.service.MemberService;
import com.example.anysale.product.dto.ProductDTO;
import com.example.anysale.product.entity.Product;
import com.example.anysale.product.repository.ProductRepository;
import com.example.anysale.product.service.ProductService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class LikeListServiceImpl implements LikeListService {

  private final LikeListRepository likeListRepository;
  private final ProductRepository productRepository;
  private final ProductService productService;  // ProductService 추가
  private final MemberService memberService;    // MemberService 추가
  private final MemberRepository memberRepository;

  @Autowired
  public LikeListServiceImpl(LikeListRepository likeListRepository, ProductRepository productRepository, ProductService productService, MemberService memberService, MemberRepository memberRepository) {
    this.likeListRepository = likeListRepository;
    this.productRepository = productRepository;
    this.productService = productService;
    this.memberService = memberService;
    this.memberRepository = memberRepository;
  }

  // 찜 목록에 상품 추가
  @Override
  public LikeList addLikeList(LikeList likeList) {
    // 상품과 회원이 유효한지 확인
    if (productService.getProductById(likeList.getProduct().getItemCode()).isEmpty()) {
      throw new EntityNotFoundException("상품을 찾을 수 없습니다.");
    }
    if (memberService.getMemberById(likeList.getMember().getId()).isEmpty()) {
      throw new EntityNotFoundException("회원 정보를 찾을 수 없습니다.");
    }
    return likeListRepository.save(likeList);
  }

  // 회원의 찜 목록 조회
  @Override
  public List<ProductDTO> getLikeList(String memberId) {
    // 회원 ID로 찜 목록 조회
    List<LikeList> likeLists = likeListRepository.findByMemberId(memberId);

    List<String> itemCodes = new ArrayList<>();
    List<ProductDTO> productDTOs = new ArrayList<>();

    for (LikeList likeList : likeLists) {
      itemCodes.add(likeList.getProduct().getItemCode());
    }

    for (String itemCode : itemCodes) {
      System.out.println("itemCode = " + itemCode);
    }

    for (LikeList likeList : likeLists) {

      Product product = productRepository.findById(likeList.getProduct().getItemCode())
          .orElse(null); // 상품을 찾지 못했을 경우 null 반환
      ProductDTO productDTO = new ProductDTO();
      if (product != null) {
        // Product 속성 값 설정
        productDTO.setItemCode(product.getItemCode());
        productDTO.setImageUrl(product.getImageUrl());
        productDTO.setTitle(product.getTitle());
        productDTO.setCategory(product.getCategory());
        productDTO.setContent(product.getContent());
        productDTO.setPrice(product.getPrice());
      }

      if (productDTO != null) {
        productDTOs.add(productDTO);
      }

    }

    return productDTOs;
  }


  //  // 찜 목록에서 특정 상품 제거
  @Override
  public LikeList removeLikeList(int likeListId) {
    return null;
  }

  // 찜 목록에서 모든 상품 제거
  @Override
  public void removeAllLikeList(String memberId) {

  }
}

//  // 찜 목록에서 특정 상품 제거
//  @Override
//  public LikeList removeLikeList(int likeListId) {
//    LikeList likeList = likeListRepository.findById(likeListId)
//        .orElseThrow(() -> new EntityNotFoundException("찜 목록이 존재하지 않습니다."));
//    likeListRepository.delete(likeList);
//    return likeList; // 제거된 likeList 반환 (필요한 경우)
//  }
//
//  // 찜 목록에서 모든 상품 제거
//  @Override
//  public void removeAllLikeList(String memberId) {
//    List<LikeList> likeLists = likeListRepository.findByMemberId(memberId);
//    likeLists.forEach(likeListRepository::delete);
//  }
//}
