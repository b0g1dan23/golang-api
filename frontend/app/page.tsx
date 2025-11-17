import Features from "@/components/homepage/Features";
import Hero from "@/components/homepage/Hero";
import LogoLoop from "@/components/homepage/LogoLoop";
import ProductImage from "@/components/homepage/ProductImage";
import Questions from "@/components/homepage/Questions";
import TestimonialsFlex from "@/components/homepage/TestimonialsFlex";

export default function Home() {
  return (
    <>
      <Hero />
      <LogoLoop />
      <ProductImage />
      <Features />
      <TestimonialsFlex />
      <Questions />
    </>
  );
}
