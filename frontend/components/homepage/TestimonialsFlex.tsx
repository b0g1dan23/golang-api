import woman_cat from "@/public/testimonials/woman_white-bg.jpg";
import Image from "next/image";
import { TiStarFullOutline } from "react-icons/ti";
import {
  AnimatedTestimonials,
  Testimonial,
} from "../ui/shadcn-io/animated-testimonials";

const data: Testimonial[] = [
  {
    quote:
      "Wallet is a great product! All of my most important information is there - credit cards, transit cards, boarding passes, tickets, and more. And I don't need to worry because it's all in one place! thanks!",
    name: "Johnny Owens",
    designation: "Product Designer at Google",
    src: "/testimonials/woman_white-bg.jpg",
  },
  {
    quote:
      "Wallet is a great product! All of my most important information is there - credit cards, transit cards, boarding passes, tickets, and more. And I don't need to worry because it's all in one place! thanks!",
    name: "Johnny Owens",
    designation: "Product Designer at Google",
    src: "/testimonials/woman_white-bg.jpg",
  },
];

const TestimonialsFlex = () => {
  return (
    <section>
      <div className="text-center">
        <span className="uppercase text-sm">Testimonials</span>
        <h2 className="text-2xl">
          What <span className="text-green-400! opacity-100!">our clients</span>{" "}
          say
        </h2>
      </div>
      <AnimatedTestimonials testimonials={data} />
    </section>
  );
};
export default TestimonialsFlex;
