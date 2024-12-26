package com.example.anysale.review.repository;

import com.example.anysale.review.entity.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ReviewRepository extends JpaRepository<Review, Integer> {

    List<Review> findBySellerId(String sellerId);

    List<Review> findByBuyerId(String buyerId);

    @Query("select m from Review m where m.buyerId = :buyerId")
    List<Review> findByBuyerIdAndSellerId(@Param("buyerId") String buyerId);

}