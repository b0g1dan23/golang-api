import Button from "@/components/ui/Button";
import Image from "next/image";
import hero_image from '@/public/hero_image.png'

const Hero = () => {
    return (
        <section className="flex items-center gap-20 max-md:flex-col max-md:text-center ">
            <div className="">
                <div className="flex flex-col gap-16">
                    <h1>SaaS Landing Page Template</h1>
                    <p>This is a template Figma file, turned into code using Anima. Learn more at AnimaApp.com</p>
                </div>
                <Button variant="secondary" className="mt-28!">Get started</Button>
            </div>

            <div className="bg-(--foreground-color)/20 rounded-4xl">
                <Image src={hero_image} alt="Hero Image" />
            </div>
        </section>
    )
}
export default Hero