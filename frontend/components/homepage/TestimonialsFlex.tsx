import woman_cat from '@/public/testimonials/woman_holding_cat.png'
import Image from 'next/image'
import { TiStarFullOutline } from "react-icons/ti";

const TestimonialsFlex = () => {
    return (
        <section>
            <div className="bg-purple-300 rounded-4xl py-32 max-md:px-12 px-64">
                <p className="text-[#2b2b2b]! opacity-100! text-[2.4rem] font-semibold">“Wallet is a great product! All of my most important information is there - credit cards, transit cards, boarding passes, tickets, and more. And I don't need to worry because it's all in one place! thanks!”</p>
                <div className="flex items-center gap-8 mt-20">
                    <div className="rounded-full overflow-hidden table">
                        <Image src={woman_cat} alt="Woman holding a cat" />
                    </div>
                    <div>
                        <p className='text-[#2b2b2b]! opacity-100!'>Johnny Owens</p>
                        <p className='text-[#2b2b2b]! opacity-60!'>Product Designer at Google</p>
                        <div className="flex items-center">
                            <TiStarFullOutline color='#2b2b2b' />
                            <TiStarFullOutline color='#2b2b2b' />
                            <TiStarFullOutline color='#2b2b2b' />
                            <TiStarFullOutline color='#2b2b2b' />
                            <TiStarFullOutline color='#2b2b2b' />
                        </div>
                    </div>
                </div>
            </div>
        </section>
    )
}
export default TestimonialsFlex