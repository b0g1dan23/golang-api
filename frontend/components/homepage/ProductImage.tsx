import Image from "next/image";
import product_image from '@/public/product_image.png'

const ProductImage = () => {
    return (
        <section>
            <div className="text-center mb-10">
                <span className="uppercase text-sm">Demo</span>
                <h2 className="text-2xl">Check out demo</h2>
            </div>
            <div className="bg-[#FDF5DF] rounded-4xl relative">
                <div className="w-[80%] h-[80%] bg-primary absolute top-1/2 left-1/2 -translate-1/2 rounded-full blur-[6rem] -z-1"></div>
                <Image src={product_image} alt="Product video/image" />
            </div>
        </section>
    )
}
export default ProductImage