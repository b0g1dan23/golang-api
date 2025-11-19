import { Button } from "@/components/ui/button";
import Image from "next/image";
import hero_image from "@/public/hero_image.png";

const Hero = () => {
  return (
    <section className="flex items-center gap-14 max-md:flex-col max-md:text-center ">
      <div className="">
        <div className="flex flex-col gap-8">
          <h1 className="text-5xl">SaaS Landing Page Template</h1>
          <p>
            This is a template Figma file, turned into code using Anima. Learn
            more at AnimaApp.com
          </p>
        </div>
        <Button
          size="lg"
          className="mt-16! bg-green-400 text-black hover:bg-green-500 hover:scale-105 active:scale-95"
        >
          Get started
        </Button>
      </div>

      <div className="bg-(--foreground-color)/20 rounded-4xl">
        <Image src={hero_image} alt="Hero Image" />
      </div>
    </section>
  );
};
export default Hero;
