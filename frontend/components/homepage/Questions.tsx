import Button from "../ui/Button"
import wallet_img from '@/public/Wallet_Gif.png'
import Image from "next/image"

const Questions = () => {
    return (
        <section className="flex gap-32 items-center justify-between max-md:flex-col max-md:text-center">
            <div className="">
                <h2>Questions?
                    <br />
                    Let&apos;s talk </h2>
                <p className="mt-12">Contact us through our 24/7 live chat. <br /> We&apos;re always happy to help!</p>
                <Button href="/contact" className="mt-32">Contact us</Button>
            </div>
            <div className="rounded-4xl overflow-hidden">
                <Image src={wallet_img} alt="Wallet Gif" />
            </div>
        </section>
    )
}
export default Questions