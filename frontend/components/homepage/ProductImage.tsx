import Image from "next/image";
import product_image from '@/public/product_image.png'

const ProductImage = () => {
    return (
        <section>
            <div className="bg-[#FDF5DF] rounded-4xl">
                <Image src={product_image} alt="Product video/image" />
            </div>
        </section>
    )
}
export default ProductImage