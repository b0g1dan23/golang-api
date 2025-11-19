import { Button } from "../ui/button";
import wallet_img from "@/public/Wallet_Gif.png";
import Image from "next/image";
import Link from "next/link";

const Questions = () => {
  return (
    <section className="flex gap-32 items-center justify-between max-md:flex-col max-md:gap-12 max-md:text-center">
      <div className="">
        <h2 className="text-3xl">
          Questions?
          <br />
          Let&apos;s talk{" "}
        </h2>
        <p className="mt-12 max-md:mt-10">
          Contact us through our 24/7 live chat. <br /> We&apos;re always happy
          to help!
        </p>
        <Link href="/contact">
          <Button className="mt-32 max-md:mt-16 bg-green-400 hover:bg-green-500 text-black hover:scale-105 active:scale-95">
            Contact us
          </Button>
        </Link>
      </div>
      <div className="rounded-4xl overflow-hidden">
        <Image src={wallet_img} alt="Wallet Gif" />
      </div>
    </section>
  );
};
export default Questions;
