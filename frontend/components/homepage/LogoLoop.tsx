import Marquee from "react-fast-marquee";
import netflix_logo from "@/public/partners/Netflix_2015_logo.svg.png"
import microsoft_logo from "@/public/partners/Microsoft_logo.png"
import apple_logo from "@/public/partners/Apple_logo_black.svg"
import accenture_logo from "@/public/partners/Accenture.svg.png"
import google_logo from "@/public/partners/Google_2015.webp"
import Image from "next/image";

const logos = [
    netflix_logo,
    microsoft_logo,
    apple_logo,
    accenture_logo,
    google_logo,
]

const LogoLoop = () => {
    return (
        <section className="border-t border-b border-neutral-700 py-16!">
            <Marquee
                gradient={false}
                speed={30}
                pauseOnHover={false}
            >
                <div className="flex items-center gap-24 max-md:gap-12 px-12!">
                    {logos.map((image, i) => (
                        <div
                            key={i}
                            className="pr-12! last:pr-0! shrink-0"
                        >
                            <Image
                                src={image}
                                alt="Partner logo"
                                className="max-h-24 w-auto grayscale-100 opacity-40" />
                        </div>
                    ))}
                </div>
            </Marquee>
        </section>
    )
}
export default LogoLoop